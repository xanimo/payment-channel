/*

 The MIT License (MIT)

 Copyright (c) 2026 bluezr

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/

#include "state.h"
#include "hex.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

/* One field per line, "key value", no quoting and no nesting. The wire format
   is JSON because it crosses a socket to another implementation; this crosses
   nothing, so it is the smallest thing that can be parsed strictly. Every field
   is validated on load and an unreadable file is refused rather than treated as
   a fresh channel, because "fresh" means a ratchet of zero. */
#define PC_STATE_MAGIC "payment-channel-state 1"

static int write_all(int fd, const char *p, size_t n)
{
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return 0; }
        p += w; n -= (size_t)w;
    }
    return 1;
}

/* txid is 64 hex characters and vout is bounded by the opening check, so the
   name needs no escaping. It is validated rather than assumed, since it becomes
   a path. */
static int outpoint_path(char *out, size_t cap, const char *dir,
                         const char *txid, int vout)
{
    if (strlen(txid) != 64 || !pc_is_hex(txid, 64)) return 0;
    if (vout < 0 || vout > 0xFFFF) return 0;
    int n = snprintf(out, cap, "%s/%s-%d.channel", dir, txid, vout);
    return n > 0 && (size_t)n < cap;
}

static const char *field(const char *buf, const char *key, size_t *len)
{
    size_t klen = strlen(key);
    const char *p = buf;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t line = eol ? (size_t)(eol - p) : strlen(p);
        if (line > klen && p[klen] == ' ' && !strncmp(p, key, klen)) {
            *len = line - klen - 1;
            return p + klen + 1;
        }
        if (!eol) break;
        p = eol + 1;
    }
    return NULL;
}

static int field_eq(const char *buf, const char *key, const char *want)
{
    size_t n = 0;
    const char *v = field(buf, key, &n);
    return v && n == strlen(want) && !memcmp(v, want, n);
}

static int field_u64(const char *buf, const char *key, uint64_t *out)
{
    size_t n = 0;
    const char *v = field(buf, key, &n);
    if (!v || n == 0 || n > 20) return 0;
    uint64_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        if (v[i] < '0' || v[i] > '9') return 0;
        if (acc > (UINT64_MAX - (uint64_t)(v[i] - '0')) / 10) return 0;
        acc = acc * 10 + (uint64_t)(v[i] - '0');
    }
    *out = acc;
    return 1;
}

void pc_state_disable(pc_state *st)
{
    if (!st) return;
    st->lock_fd = -1;
    st->path[0] = '\0';
    st->tmp[0]  = '\0';
    st->lock[0] = '\0';
}

void pc_state_close(pc_state *st)
{
    if (!st || st->lock_fd < 0) return;
    close(st->lock_fd);       /* releases the flock */
    st->lock_fd = -1;
}

pc_result pc_state_open(pc_state *st, const char *dir, pc_channel *ch)
{
    if (!st || !dir || !ch) return PC_ERR_ARG;
    pc_state_disable(st);

    if (!outpoint_path(st->path, sizeof(st->path), dir,
                       ch->funding_txid, ch->funding_vout))
        return PC_ERR_ARG;
    /* snprintf returns the length it wanted, not negative, on truncation, so
       the bound is >=size: at the top of path's range the derived names would
       otherwise collapse onto path itself, making tmp the live file unlink()
       removes and lock the data file flock holds by unlinked inode. */
    if (snprintf(st->tmp,  sizeof(st->tmp),  "%s.tmp",  st->path) >= (int)sizeof(st->tmp))  return PC_ERR_ARG;
    if (snprintf(st->lock, sizeof(st->lock), "%s.lock", st->path) >= (int)sizeof(st->lock)) return PC_ERR_ARG;

    /* The lock is its own file because the data file gets renamed over, and a
       lock follows the inode rather than the name. Locking the data file held
       an unlinked inode from the first save onwards while the next process
       locked the new one and saw nothing in its way. This one is created once
       and never replaced, so the name and the inode stay the same thing. */
    int lfd = open(st->lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lfd < 0) return PC_ERR_ARG;

    /* Non-blocking: a second session on one outpoint is refused, not queued.
       Two peers negotiating against one channel at once have no interleaving
       that leaves the ratchet meaning anything. */
    if (flock(lfd, LOCK_EX | LOCK_NB) != 0) {
        close(lfd);
        return PC_ERR_STATE;
    }
    st->lock_fd = lfd;

    int fd = open(st->path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) { ch->paid_to_bob_koinu = 0; return PC_OK; }
        pc_state_close(st);
        return PC_ERR_ARG;
    }

    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz < 0 || sz > 1024 * 1024) { close(fd); pc_state_close(st); return PC_ERR_ARG; }
    if (sz == 0) { close(fd); ch->paid_to_bob_koinu = 0; return PC_OK; }

    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { close(fd); pc_state_close(st); return PC_ERR_ARG; }
    if (lseek(fd, 0, SEEK_SET) != 0) { free(buf); close(fd); pc_state_close(st); return PC_ERR_ARG; }
    ssize_t got = read(fd, buf, (size_t)sz);
    close(fd);
    if (got != sz) { free(buf); pc_state_close(st); return PC_ERR_ARG; }
    buf[sz] = '\0';

    pc_result rc = PC_ERR_ARG;
    if (!field_eq(buf, "magic", PC_STATE_MAGIC)) goto out;

    /* The stored channel has to be the one this session just built. One
       outpoint presented under two sets of keys or two locktimes is not a
       reconnection, and loading the ratchet across them would apply one
       channel's payments to another. */
    rc = PC_ERR_SCRIPT;
    if (!field_eq(buf, "redeem", ch->redeem_script_hex)) goto out;
    if (!field_eq(buf, "alice",  ch->alice_pubkey_hex)) goto out;
    if (!field_eq(buf, "bob",    ch->bob_pubkey_hex))   goto out;

    uint64_t v = 0;
    rc = PC_ERR_ARG;
    if (!field_u64(buf, "locktime", &v) || v != ch->locktime)       goto out;
    if (!field_u64(buf, "capacity", &v) || v != ch->capacity_koinu) goto out;

    /* A closed channel does not reopen. The close is the last thing that
       happens on an outpoint, and a session after it is asking to be shipped
       against a transaction the closed one intends to broadcast. */
    if (field_u64(buf, "closed", &v) && v) { rc = PC_ERR_CLOSED; goto out; }

    rc = PC_ERR_ARG;
    /* absent in files written before it was recorded, which is why it is not
       an error to be missing: zero means nobody has asked a chain yet */
    if (field_u64(buf, "fheight", &v) && v <= 0xffffffffULL)
        ch->funding_height = (uint32_t)v;

    if (!field_u64(buf, "paid", &v)) goto out;

    /* A stored ratchet above the capacity is a corrupt file, not a rich
       channel, and taking it would refuse every honest payment after it. */
    rc = PC_ERR_AMOUNT;
    if (v > ch->capacity_koinu) goto out;

    ch->paid_to_bob_koinu = v;
    rc = PC_OK;
out:
    free(buf);
    if (rc != PC_OK) pc_state_close(st);
    return rc;
}

static pc_result state_write(pc_state *st, const pc_channel *ch,
                             const char *best_tx_hex, int closed, int sent)
{
    if (!st || !ch) return PC_ERR_ARG;
    if (st->lock_fd < 0) return PC_OK;            /* state is off */
    if (!best_tx_hex) best_tx_hex = "";

    /* Temporary, fsync, rename. A crash between the write and the rename
       leaves the previous ratchet intact, which costs Alice a retry; the other
       order costs Bob the payment he already acked. */
    int fd = open(st->tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return PC_ERR_STATE;

    char head[PC_MAX_SCRIPT_HEX + 512];
    int n = snprintf(head, sizeof(head),
                     "magic %s\n"
                     "redeem %s\n"
                     "alice %s\n"
                     "bob %s\n"
                     "locktime %u\n"
                     "fheight %u\n"
                     "capacity %llu\n"
                     "paid %llu\n"
                     "closed %d\n"
                     "sent %d\n"
                     "tx ",
                     PC_STATE_MAGIC, ch->redeem_script_hex,
                     ch->alice_pubkey_hex, ch->bob_pubkey_hex,
                     (unsigned)ch->locktime, (unsigned)ch->funding_height,
                     (unsigned long long)ch->capacity_koinu,
                     (unsigned long long)ch->paid_to_bob_koinu,
                     closed ? 1 : 0, sent ? 1 : 0);
    int ok = n > 0 && (size_t)n < sizeof(head) &&
             write_all(fd, head, (size_t)n) &&
             write_all(fd, best_tx_hex, strlen(best_tx_hex)) &&
             write_all(fd, "\n", 1) &&
             fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (!ok) { unlink(st->tmp); return PC_ERR_STATE; }

    if (rename(st->tmp, st->path) != 0) { unlink(st->tmp); return PC_ERR_STATE; }

    /* The rename is only durable once the directory entry is. Without this a
       power loss can leave the directory pointing at the old name. */
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", st->path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        int dfd = open(dir, O_RDONLY | O_CLOEXEC);
        if (dfd >= 0) { fsync(dfd); close(dfd); }
    }
    return PC_OK;
}

pc_result pc_state_adopt(pc_state *st, const char *dir,
                         const char *txid_hex, int vout,
                         pc_channel *ch, char *tx, size_t txcap,
                         int *closed, int *sent)
{
    if (!st || !dir || !txid_hex || !ch || !tx || txcap == 0) return PC_ERR_ARG;
    pc_state_disable(st);
    memset(ch, 0, sizeof(*ch));
    tx[0] = '\0';
    if (closed) *closed = 0;
    if (sent) *sent = 0;

    if (!outpoint_path(st->path, sizeof(st->path), dir, txid_hex, vout))
        return PC_ERR_ARG;
    /* snprintf returns the length it wanted, not negative, on truncation, so
       the bound is >=size: at the top of path's range the derived names would
       otherwise collapse onto path itself, making tmp the live file unlink()
       removes and lock the data file flock holds by unlinked inode. */
    if (snprintf(st->tmp,  sizeof(st->tmp),  "%s.tmp",  st->path) >= (int)sizeof(st->tmp))  return PC_ERR_ARG;
    if (snprintf(st->lock, sizeof(st->lock), "%s.lock", st->path) >= (int)sizeof(st->lock)) return PC_ERR_ARG;

    int lfd = open(st->lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lfd < 0) return PC_ERR_ARG;
    if (flock(lfd, LOCK_EX | LOCK_NB) != 0) { close(lfd); return PC_ERR_STATE; }
    st->lock_fd = lfd;

    int fd = open(st->path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { pc_state_close(st); return PC_ERR_ARG; }
    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz <= 0 || sz > 1024 * 1024) { close(fd); pc_state_close(st); return PC_ERR_ARG; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { close(fd); pc_state_close(st); return PC_ERR_ARG; }
    if (lseek(fd, 0, SEEK_SET) != 0) { free(buf); close(fd); pc_state_close(st); return PC_ERR_ARG; }
    ssize_t got = read(fd, buf, (size_t)sz);
    close(fd);
    if (got != sz) { free(buf); pc_state_close(st); return PC_ERR_ARG; }
    buf[sz] = '\0';

    pc_result rc = PC_ERR_ARG;
    if (!field_eq(buf, "magic", PC_STATE_MAGIC)) goto out;

    size_t n = 0;
    const char *v = field(buf, "redeem", &n);
    if (!v || n == 0 || n + 1 > sizeof(ch->redeem_script_hex)) goto out;
    memcpy(ch->redeem_script_hex, v, n); ch->redeem_script_hex[n] = '\0';

    v = field(buf, "alice", &n);
    if (!v || n + 1 > sizeof(ch->alice_pubkey_hex)) goto out;
    memcpy(ch->alice_pubkey_hex, v, n); ch->alice_pubkey_hex[n] = '\0';

    v = field(buf, "bob", &n);
    if (!v || n + 1 > sizeof(ch->bob_pubkey_hex)) goto out;
    memcpy(ch->bob_pubkey_hex, v, n); ch->bob_pubkey_hex[n] = '\0';

    uint64_t u = 0;
    if (!field_u64(buf, "locktime", &u) || u == 0 || u > 0xffffffffULL) goto out;
    ch->locktime = (uint32_t)u;
    if (!field_u64(buf, "capacity", &u)) goto out;
    ch->capacity_koinu = u;
    if (!field_u64(buf, "paid", &u) || u > ch->capacity_koinu) goto out;
    ch->paid_to_bob_koinu = u;
    if (field_u64(buf, "fheight", &u) && u <= 0xffffffffULL)
        ch->funding_height = (uint32_t)u;

    if (closed && field_u64(buf, "closed", &u)) *closed = u ? 1 : 0;
    if (sent && field_u64(buf, "sent", &u)) *sent = u ? 1 : 0;

    snprintf(ch->funding_txid, sizeof(ch->funding_txid), "%s", txid_hex);
    ch->funding_vout = vout;

    /* The transaction is the reason a sweep exists, so a file carrying one too
       long for the caller's buffer is an error rather than a channel with an
       empty one: silently sweeping without broadcasting would retire a channel
       and drop the payment. */
    v = field(buf, "tx", &n);
    if (v) {
        if (n + 1 > txcap) goto out;
        memcpy(tx, v, n); tx[n] = '\0';
    }
    rc = PC_OK;
out:
    free(buf);
    if (rc != PC_OK) pc_state_close(st);
    return rc;
}

pc_result pc_state_save(pc_state *st, const pc_channel *ch,
                        const char *best_tx_hex)
{
    return state_write(st, ch, best_tx_hex, 0, 0);
}

pc_result pc_state_retire(pc_state *st, const pc_channel *ch,
                          const char *best_tx_hex)
{
    return state_write(st, ch, best_tx_hex, 1, 0);
}

pc_result pc_state_mark_sent(pc_state *st, const pc_channel *ch,
                             const char *best_tx_hex, int keep_closed)
{
    return state_write(st, ch, best_tx_hex, keep_closed ? 1 : 0, 1);
}
