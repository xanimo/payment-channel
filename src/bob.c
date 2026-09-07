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

/* The merchant. Bob is paid, so Bob is the one who has to be careful.
 *
 * He is told nothing about the channel in advance. Alice asks, he answers with
 * the key he will sign with, and everything else he learns from the opening
 * PSBT and checks for himself: the redeem script names him, the locktime
 * outlasts the work, the funding transaction really pays the channel, and each
 * payment really pays him more than the last. Then he prices the order and
 * invoices for it.
 *
 * The one thing he cannot do from here is see the chain, so the height he
 * measures the locktime against is given to him, and confirming the funding is
 * the operator's job. */

#include "common.h"
#include "hex.h"
#include "state.h"

#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>

#include <sys/stat.h>

#include <ctype.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_ORDERS 64

/* A stalled peer must not starve the rest, so each connection is handled in its
   own process. The accept loop returns to accept() the moment it has forked,
   and a peer that holds its socket only holds its own child, reaped by the wire
   timeout. Bounded so the fork-per-connection is not itself a way to exhaust
   pids: past the cap new connections are dropped rather than served. */
#define MAX_CONNS 64

/* Default cap on live connections from any one source address, so a single
   host cannot take every slot. Distributed sources defeat it and a proxy or
   tunnel makes every peer share one address, so it is overridable with
   --max-per-ip (0 disables). It does not replace a firewall connlimit. */
#define DEFAULT_MAX_PER_IP 16

/* Per-connection resource bounds, set in the child so one connection cannot
   run the box out of CPU or address space. Generous: an honest session uses
   milliseconds of CPU and a few tens of MB, so only a runaway trips these. */
#define CHILD_CPU_SECONDS   30
#define CHILD_AS_BYTES      (512UL * 1024 * 1024)

/* Address sanitizer reserves a shadow mapping far larger than any address space
   limit worth setting, so a child that caps RLIMIT_AS under it dies on its first
   mmap with "Failed to mmap" before serving anything. That is why the forking
   server had never been run under asan at all. The cap is a production defence,
   so it is kept everywhere except the build that cannot tolerate it. */
#if defined(__SANITIZE_ADDRESS__)          /* gcc */
#  define PC_ADDRESS_LIMIT_UNAVAILABLE 1
#elif defined(__has_feature)                /* clang, and it must nest */
#  if __has_feature(address_sanitizer)
#    define PC_ADDRESS_LIMIT_UNAVAILABLE 1
#  endif
#endif

static void limit_child(void)
{
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = CHILD_CPU_SECONDS;
    setrlimit(RLIMIT_CPU, &rl);
#ifndef PC_ADDRESS_LIMIT_UNAVAILABLE
    rl.rlim_cur = rl.rlim_max = CHILD_AS_BYTES;
    setrlimit(RLIMIT_AS, &rl);
#endif
}

static void usage(void)
{
    fprintf(stderr,
      "usage: bob --wif WIF|@FILE|- [--listen [HOST:]PORT] [--testnet|--regtest]\n"
      "           [--height N | --height-file PATH] [--height-max-age SEC]\n"
      "           [--min-slack N] [--state DIR] [--price DOGE ...]\n"
      "           [--confirm-cmd CMD] [--min-depth N] [--broadcast-cmd CMD]\n"
      "       bob --sweep --state DIR --height-file PATH [--broadcast-cmd CMD]\n"
      "           [--sweep-margin N] [--confirm-cmd CMD]\n"
      "           [--max-per-ip N] [--once]\n"
      "       bob --wif WIF|@FILE|- --pubkey\n"
      "\n"
      "  --wif @FILE reads the key from a file (mode 0600) and - from stdin;\n"
      "  a bare key is left in argv where ps can read it, so prefer @FILE.\n"
      "  --price is what each order costs, charged in the order given.\n"
      "  --height is the current chain height; Bob cannot see the chain and\n"
      "  refuses a channel whose locktime is not --min-slack blocks above it.\n"
      "  --max-per-ip caps live connections per source address (0 disables).\n");
}

/* Everything one connection knows. */
typedef struct {
    pc_channel ch;
    pc_state   st;              /* the outpoint's lock and ratchet on disk */
    char      *best;            /* newest transaction worth broadcasting */
    uint64_t   best_amount;
    uint64_t   owed;            /* cumulative total invoiced so far */
    int        order;
} session;

/* A reason longer than the field is copied in truncated, and the peer is told
   something that trails off mid-word. test_channel holds pc_strerror to the
   field's size, but reasons written here as literals had nothing checking them
   and two arrived at exactly one character over. Silent is the part that makes
   it a defect, so a truncation now says so in Bob's own log where the operator
   will see it. */
static int send_reject(int fd, const char *why)
{
    pc_envelope out;
    memset(&out, 0, sizeof(out));
    out.type = PC_MSG_REJECT;
    if (snprintf(out.addr, sizeof(out.addr), "%s", why) >= (int)sizeof(out.addr))
        fprintf(stderr, "reject reason truncated at %zu: %s\n",
                sizeof(out.addr) - 1, why);
    snprintf(out.psbt_hex, sizeof(out.psbt_hex), "01");
    fprintf(stderr, "reject: %s\n", why);
    return pc_wire_send(fd, &out);
}

/* [3][4][D] The opening. Bob learns the channel from the PSBT and refuses it
   unless every part of it is one he checked himself. */
/* The height Bob measures a locktime against, re-read for every channel.
 *
 * --height is a number from the operator that is correct once. min-slack is
 * checked against it at open, so a process running for a day is comparing a
 * locktime to a height a day old, and the margin it thinks it has erodes
 * silently until a channel whose locktime has already passed still looks like
 * it has room. Alice's refund is spendable the moment that happens.
 *
 * A file is the whole interface: anything that can see a chain writes a decimal
 * height into it, dogecoin-cli getblockcount or an spv wallet, and Bob reads it
 * without linking to any of them. Its age is what makes it trustworthy, so a
 * file nobody is updating is refused rather than believed. */
static int read_height_file(const char *path, unsigned max_age,
                            uint32_t *out, const char **why)
{
    struct stat sb;
    if (stat(path, &sb) != 0) { *why = "height file is missing"; return 0; }

    time_t now = time(NULL);
    if (now > sb.st_mtime && (unsigned long)(now - sb.st_mtime) > max_age) {
        *why = "height file is stale";
        return 0;
    }

    FILE *f = fopen(path, "r");
    if (!f) { *why = "height file will not open"; return 0; }
    char buf[32] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) { *why = "height file is empty"; return 0; }

    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(buf, &end, 10);
    if (errno || end == buf || v == 0 || v > UINT32_MAX) {
        *why = "height file is not a height";
        return 0;
    }
    while (end && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) end++;
    if (end && *end) { *why = "height file is not a height"; return 0; }

    *out = (uint32_t)v;
    return 1;
}

/* Is the funding output real, buried, unspent, and worth what Alice said?
 *
 * Everything else Bob checks about the funding is checked against a transaction
 * Alice handed him. She never has to have broadcast it. A confirmation backend
 * is the only thing that turns "she showed me a transaction" into "the chain
 * has this output", and it answers the three questions that matter at once:
 * present, deep enough, and not already spent.
 *
 * The command is run with execvp and an argv array, never a shell, because the
 * txid on that command line came off the wire. It gets its own deadline too: a
 * backend that hangs would otherwise be a way to pin Bob's children open, which
 * is the thing wire.c has two timeouts to prevent.
 *
 * The contract is koinu's kw outpoint: argv of --watch ADDR --outpoint TXID:VOUT,
 * exit 0 when unspent and confirmed, 3 when not, printing "depth N" and
 * "value N koinu". Any other backend wraps to the same shape. */
/* Shorter than the peer's per-read budget on purpose. A backend that takes
   longer than PC_WIRE_IO_SEC cannot produce a reject Alice is still there to
   read: she times out first and gets a dropped socket instead of a reason. A
   cold backend that needs to sync headers is warmed out of band, which is what
   an on-disk header cache is for. */
#define PC_CONFIRM_SECONDS 3
#define PC_CONFIRM_MAX_ARGV 32

/* Run (cmd), split into argv, with (extra) appended and (feed) written to its
   stdin. Shared by the confirmation and the broadcast because they differ only
   in their arguments and their budget. */
static int run_backend(const char *cmd, const char *const *extra, size_t nextra,
                       const char *feed, unsigned seconds,
                       char *out, size_t cap, int *status)
{
    int fds[2], in[2];
    if (pipe(fds) != 0) return 0;
    if (pipe(in) != 0) { close(fds[0]); close(fds[1]); return 0; }

    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); close(in[0]); close(in[1]); return 0; }
    if (pid == 0) {
        close(fds[0]); close(in[1]);
        dup2(fds[1], STDOUT_FILENO);
        dup2(in[0], STDIN_FILENO);
        close(fds[1]); close(in[0]);

        /* The command is split on spaces because the backend it exists for
           needs its own arguments: kw outpoint requires --node, so a single
           path could never invoke it and the documented form did not run. It
           is still not a shell. The split is over the operator's own argument
           and the two values appended after it are a validated address and a
           validated outpoint, so nothing off the wire reaches argv unchecked. */
        char *argv[PC_CONFIRM_MAX_ARGV];
        size_t argc = 0;
        char split[512];
        snprintf(split, sizeof(split), "%s", cmd);
        for (char *tok = strtok(split, " \t");
             tok && argc + nextra + 1 < PC_CONFIRM_MAX_ARGV;
             tok = strtok(NULL, " \t"))
            argv[argc++] = tok;
        if (argc == 0) _exit(127);
        for (size_t i = 0; i < nextra; i++) argv[argc++] = (char *)extra[i];
        argv[argc] = NULL;
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fds[1]); close(in[0]);

    if (feed) {
        size_t left = strlen(feed);
        while (left) {
            ssize_t w = write(in[1], feed, left);
            if (w <= 0) { if (w < 0 && errno == EINTR) continue; break; }
            feed += w; left -= (size_t)w;
        }
    }
    close(in[1]);

    size_t n = 0;
    time_t deadline = time(NULL) + seconds;
    int timed_out = 0;
    for (;;) {
        struct pollfd pfd = { fds[0], POLLIN, 0 };
        time_t left = deadline - time(NULL);
        if (left <= 0) { timed_out = 1; break; }
        int pr = poll(&pfd, 1, (int)(left * 1000));
        if (pr <= 0) { if (pr == 0) timed_out = 1; break; }
        if (n + 1 >= cap) break;
        ssize_t r = read(fds[0], out + n, cap - 1 - n);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) break;
        n += (size_t)r;
    }
    out[n] = '\0';
    close(fds[0]);

    if (timed_out) kill(pid, SIGKILL);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
    if (timed_out) return 0;
    *status = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    return 1;
}

/* "depth 12" or "value 100000000 koinu" out of that one line */
static int confirm_field(const char *s, const char *key, unsigned long long *out)
{
    size_t klen = strlen(key);
    for (const char *p = s; (p = strstr(p, key)) != NULL; p += klen) {
        if (p != s && p[-1] != ' ' && p[-1] != '\n') continue;
        const char *v = p + klen;
        if (*v != ' ') continue;
        v++;
        if (*v < '0' || *v > '9') continue;
        char *end = NULL;
        errno = 0;
        unsigned long long acc = strtoull(v, &end, 10);
        if (errno || end == v) return 0;
        *out = acc;
        return 1;
    }
    return 0;
}

static int run_confirm(const char *cmd, const char *addr, const char *outpoint,
                       char *out, size_t cap, int *status)
{
    const char *extra[4] = { "--watch", addr, "--outpoint", outpoint };
    return run_backend(cmd, extra, 4, NULL, PC_CONFIRM_SECONDS,
                       out, cap, status);
}

/* Hand the transaction to the chain rather than to the operator.
 *
 * Bob printed it and someone else had to broadcast it, which left the money
 * sitting between the last payment and whenever that person got round to it.
 * That window is the one Alice's refund is racing, so the shorter it is the
 * less the timeout matters. It is also where a funding output can be spent out
 * from under a transaction Bob is still holding.
 *
 * The contract is koinu's kw send: --tx - reads the hex from stdin, exit 0 with
 * "broadcast:" when no reject came back, non-zero and "rejected: <reason>"
 * otherwise. p2p has no positive acknowledgement, so no reject is the strongest
 * answer there is and the wording says so rather than claiming acceptance. */
#define PC_BROADCAST_SECONDS 30

static int broadcast(const char *cmd, const char *raw_tx_hex)
{
    const char *extra[2] = { "--tx", "-" };
    char out[512];
    int status = -1;
    if (!run_backend(cmd, extra, 2, raw_tx_hex, PC_BROADCAST_SECONDS,
                     out, sizeof(out), &status)) {
        printf("broadcast did not answer in %ds, broadcast it yourself\n",
               PC_BROADCAST_SECONDS);
        return 0;
    }
    for (char *p = out; *p; p++) if (*p == '\n') *p = ' ';
    if (status == 0) { printf("%s\n", out); return 1; }
    printf("broadcast refused (%d) %s, broadcast it yourself\n", status, out);
    return 0;
}

/* 1 confirmed, 0 definitively not there, -1 could not be determined.
 *
 * The third is not a detail. A sweep that treats "the backend fell over" the
 * same as "the output is gone" retires the channel and drops the payment,
 * which is the one outcome worse than doing nothing. An open refuses on
 * anything but 1; a sweep only acts on 0. */
static int funding_is_confirmed(const char *cmd, const pc_channel *ch,
                                unsigned min_depth, const char **why)
{
    if (strlen(ch->funding_txid) != 64 || ch->funding_vout < 0) {
        *why = "funding outpoint is malformed";
        return -1;
    }
    char outpoint[80];
    if (snprintf(outpoint, sizeof(outpoint), "%s:%d",
                 ch->funding_txid, ch->funding_vout) < 0) {
        *why = "funding outpoint is malformed";
        return -1;
    }

    char buf[512];
    int status = -1;
    if (!run_confirm(cmd, ch->p2sh_address, outpoint, buf, sizeof(buf), &status)) {
        *why = "confirmation backend did not reply";
        return -1;
    }
    /* 3 is a definite no: the backend looked and the output is not in the
       unspent set. 4 is kwd saying it did not look far enough back, which is
       not the same answer at all, and reading it as a no would have the sweep
       retire a live channel. Everything else is a backend that could not tell
       us. Only 3 is allowed to be terminal. */
    if (status == 3) { *why = "funding is unconfirmed or spent"; return 0; }
    if (status == 4) { *why = "funding not in the scanned range"; return -1; }
    if (status != 0) { *why = "confirmation backend failed";     return -1; }

    unsigned long long depth = 0, value = 0;
    if (!confirm_field(buf, "depth", &depth)) {
        *why = "confirmation gave no depth";
        return -1;
    }
    if (depth < min_depth) { *why = "funding is not buried deep enough"; return 0; }

    /* The capacity came from the transaction Alice supplied. The chain is the
       only thing that can say whether that transaction is the one that paid. */
    if (confirm_field(buf, "value", &value) && value != ch->capacity_koinu) {
        *why = "funding is not worth what it says";
        return 0;
    }
    return 1;
}

/* One pass over the state directory, broadcasting what is about to expire.
 *
 * A session that ends without a close leaves the payment in its state file and
 * the child exits. Nothing read that transaction back, so if Alice paid and
 * simply walked away it sat there until the locktime passed and her refund took
 * back the money and the goods with it. The ratchet and --broadcast-cmd each
 * solved half of this and the halves were not joined.
 *
 * A pass rather than a thread, because Bob has no loop that outlives a
 * connection and adding one would be a bigger change than the problem. Run it
 * from cron or a systemd timer, as often as suits the margin.
 *
 * A channel a live session holds is skipped: the lock is what says so, and
 * sweeping one out from under a peer mid-payment would broadcast a state older
 * than the one being negotiated. */
static int do_sweep(const char *dir, const char *height_file, unsigned max_age,
                    const char *broadcast_cmd, const char *confirm_cmd,
                    unsigned min_depth, unsigned margin, pc_chain chain)
{
    const char *why = "";
    uint32_t height = 0;
    if (!read_height_file(height_file, max_age, &height, &why)) {
        fprintf(stderr, "bob: %s: %s\n", height_file, why);
        return 1;
    }

    DIR *d = opendir(dir);
    if (!d) { fprintf(stderr, "bob: cannot read %s\n", dir); return 1; }

    int swept = 0, held = 0, waiting = 0, dead = 0, unknown = 0, confirmed = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        /* <64 hex>-<vout>.channel, and nothing else in the directory */
        char txid[65];
        int vout = -1;
        size_t nlen = strlen(e->d_name);
        if (nlen < 68 || strcmp(e->d_name + nlen - 8, ".channel") != 0) continue;
        if (e->d_name[64] != '-') continue;
        memcpy(txid, e->d_name, 64); txid[64] = '\0';
        if (!pc_is_hex(txid, 64)) continue;
        if (sscanf(e->d_name + 65, "%d.channel", &vout) != 1 || vout < 0) continue;

        pc_state st;
        pc_channel ch;
        char tx[PC_MAX_PSBT_HEX];
        int closed = 0, already_sent = 0;
        pc_result r = pc_state_adopt(&st, dir, txid, vout, &ch, tx, sizeof(tx),
                                     &closed, &already_sent);
        if (r == PC_ERR_STATE) { held++; continue; }
        if (r != PC_OK) {
            fprintf(stderr, "sweep    %s:%d unreadable\n", txid, vout);
            continue;
        }
        /* A closed channel is not a finished one. Closing refuses new sessions
           on the outpoint; what finishes it is that outpoint being spent.
           skipping closed channels here switched the safety net off at exactly
           the moment it was needed: a close with no --broadcast-cmd, or one
           interrupted between retiring and sending, left the transaction in
           the file with nothing that would ever send it. */
        if (tx[0] == '\0') { pc_state_close(&st); continue; }

        /* The file stores the parts, not the whole channel: no p2sh address
           because it is derivable, and no chain because it is the operator's.
           Rebuilding from the parts produces both, and comparing the script it
           produces to the stored one is the same canonical check used
           everywhere else, so a file that has been edited stops here. */
        {
            pc_channel canon;
            if (pc_channel_init(&canon, ch.alice_pubkey_hex, ch.bob_pubkey_hex,
                                ch.locktime, chain) != PC_OK ||
                strcmp(canon.redeem_script_hex, ch.redeem_script_hex) != 0) {
                fprintf(stderr, "sweep    %s:%d does not rebuild, skipping\n",
                        txid, vout);
                pc_state_close(&st);
                continue;
            }
            snprintf(ch.p2sh_address, sizeof(ch.p2sh_address), "%s",
                     canon.p2sh_address);
        }

        /* Ask the chain first, because what to do next depends on whether the
           funding output is still there rather than on what was sent. */
        if (confirm_cmd) {
            int ok = funding_is_confirmed(confirm_cmd, &ch, min_depth, &why);
            if (ok < 0) {
                /* Not knowing is a reason to try again, never a reason to
                   retire: the transaction is the payment. */
                printf("sweep    %s:%d %s, leaving it for the next pass\n",
                       txid, vout, why);
                unknown++;
                pc_state_close(&st);
                continue;
            }
            if (ok == 0) {
                /* The outpoint is spent. If this is the transaction that spent
                   it, the channel is genuinely finished; if something else did,
                   there is nothing left to broadcast either way. */
                printf("sweep    %s:%d %s\n", txid, vout,
                       already_sent ? "the close confirmed" : why);
                pc_state_retire(&st, &ch, tx);
                if (already_sent) confirmed++; else dead++;
                pc_state_close(&st);
                continue;
            }
        }

        /* Still unspent. An open channel waits for the locktime to come close
           enough that waiting risks the refund becoming spendable first, since
           sending early costs a customer the rest of the channel. A closed one
           has no rest of the channel to lose and is due now. */
        if (!closed && (uint64_t)ch.locktime > (uint64_t)height + margin) {
            waiting++;
            pc_state_close(&st);
            continue;
        }

        printf("sweep    %s:%d locktime %u, height %u, %" PRIu64 " koinu%s%s\n",
               txid, vout, ch.locktime, height, ch.paid_to_bob_koinu,
               closed ? ", closed and unconfirmed" : "",
               already_sent ? ", still unspent, sending again" : "");
        if (broadcast_cmd) {
            if (broadcast(broadcast_cmd, tx)) {
                /* Marked as sent, not retired. kw send says "no reject" and
                   means it: p2p has no acknowledgement, so a peer may never
                   relay this and a mempool may drop it later. The pass that
                   finds the outpoint spent is the one that closes the channel,
                   and re-sending in between is harmless. Without a
                   confirmation backend nothing will ever say more than this,
                   so there it retires and says so. */
                /* The write is checked. It failing is safe, since an
                   unrecorded send is simply sent again, but the summary is the
                   only thing telling an operator this ran and it must not
                   claim a record it does not have. */
                pc_result w = confirm_cmd
                                ? pc_state_mark_sent(&st, &ch, tx, closed)
                                : pc_state_retire(&st, &ch, tx);
                if (w != PC_OK)
                    fprintf(stderr, "sweep    %s:%d sent but not recorded\n",
                            txid, vout);
                swept++;
            }
        } else {
            printf("%s\n", tx);
            swept++;
        }
        pc_state_close(&st);
    }
    closedir(d);
    printf("sweep    %d broadcast, %d confirmed, %d waiting, %d held by a "
           "session, %d dead, %d undetermined\n",
           swept, confirmed, waiting, held, dead, unknown);
    fflush(stdout);
    return 0;
}

static int handle_open(int fd, session *s, const pc_envelope *in,
                       const char *wif, pc_chain chain,
                       const char *bob_pub, uint32_t height, uint32_t slack,
                       const char *state_dir,
                       const char *height_file, unsigned height_max_age,
                       const char *confirm_cmd, unsigned min_depth)
{
    (void)wif;
    dogecoin_psbt *psbt = NULL;
    if (!dogecoin_psbt_from_hex(in->psbt_hex, &psbt) || !psbt)
        return send_reject(fd, "unreadable psbt"), 0;

    unsigned char rbuf[520];
    size_t rlen = 0;
    int ok = dogecoin_psbt_num_inputs(psbt) == 1 &&
             dogecoin_psbt_input_get_redeemscript(psbt, 0, rbuf, sizeof(rbuf), &rlen);
    dogecoin_psbt_free(psbt);
    if (!ok) return send_reject(fd, "no redeem script"), 0;

    char rhex[PC_MAX_SCRIPT_HEX];
    if (rlen * 2 + 1 > sizeof(rhex)) return send_reject(fd, "script too long"), 0;
    utils_bin_to_hex(rbuf, rlen, rhex);

    /* who is this channel between, and until when */
    char alice_pub[PUBKEYHEXLEN], named_bob[PUBKEYHEXLEN];
    uint32_t locktime = 0;
    if (pc_redeem_parse(rhex, alice_pub, named_bob, &locktime) != PC_OK)
        return send_reject(fd, "not a channel script"), 0;
    if (strcmp(named_bob, bob_pub) != 0)
        return send_reject(fd, "script does not name me"), 0;

    pc_result r = pc_channel_init(&s->ch, alice_pub, bob_pub, locktime, chain);
    if (r != PC_OK) return send_reject(fd, "cannot build channel"), 0;

    /* Read it here, not at startup: this is the moment the margin is decided. */
    if (height_file) {
        const char *why = "height file";
        if (!read_height_file(height_file, height_max_age, &height, &why))
            return send_reject(fd, why), 0;
    }

    uint64_t capacity = 0;
    r = pc_channel_open_accept(&s->ch, in->psbt_hex, in->tx_hex,
                               height, slack, &capacity);
    if (r != PC_OK) {
        return send_reject(fd, r == PC_ERR_STATE ? "locktime too near"
                                                 : "funding does not check out"), 0;
    }

    /* Everything above checked the funding against a transaction Alice sent.
       This is the first thing that checks it against a chain. */
    if (confirm_cmd) {
        const char *why = "funding is not confirmed";
        if (funding_is_confirmed(confirm_cmd, &s->ch, min_depth, &why) != 1)
            return send_reject(fd, why), 0;
        printf("funding  confirmed to at least %u blocks\n", min_depth);
    }

    /* The ratchet belongs to the outpoint, not to this connection. Claim it
       before anything is invoiced: without this each session starts at zero and
       one funding output pays for goods as many times as Alice reconnects. */
    if (state_dir) {
        pc_result sr = pc_state_open(&s->st, state_dir, &s->ch);
        if (sr == PC_ERR_STATE)  return send_reject(fd, "channel is in use"), 0;
        if (sr == PC_ERR_CLOSED) return send_reject(fd, pc_strerror(sr)), 0;
        if (sr == PC_ERR_SCRIPT) return send_reject(fd, "outpoint is another channel"), 0;
        if (sr != PC_OK)         return send_reject(fd, "cannot claim channel"), 0;

        /* Invoices are cumulative totals, so they carry on from what the
           channel has already paid rather than restarting. Without this a
           resumed channel invoices an amount its own ratchet refuses, and the
           replay is fixed by making the channel unusable, which is not a fix. */
        s->owed = s->ch.paid_to_bob_koinu;
    }

    char cap_s[32];
    pc_koinu_to_doge(capacity, cap_s, sizeof(cap_s));
    printf("channel  %s\n", s->ch.p2sh_address);
    printf("funding  %s:%d worth %s DOGE, locktime %u (height %u)\n",
           s->ch.funding_txid, s->ch.funding_vout, cap_s, locktime, height);
    if (s->ch.paid_to_bob_koinu)
        printf("resumed  %" PRIu64 " koinu already paid on this outpoint\n",
               s->ch.paid_to_bob_koinu);
    fflush(stdout);

    pc_envelope out;
    memset(&out, 0, sizeof(out));
    out.type = PC_MSG_ACCEPT;
    snprintf(out.ref, sizeof(out.ref), "%s", s->ch.funding_txid);
    out.vout = s->ch.funding_vout;
    out.to_bob_koinu = capacity;
    snprintf(out.psbt_hex, sizeof(out.psbt_hex), "01");
    return pc_wire_send(fd, &out);
}

/* Whether another order is due, and what it would bring the running total to.
   Bob has to answer this before the ack goes out rather than discover it inside
   send_invoice(), so the two share it and cannot disagree. */
static int invoice_due(const session *s, const char **prices, int nprices,
                       uint64_t *total_out)
{
    if (s->order >= nprices) return 0;
    uint64_t amount = 0;
    if (pc_doge_to_koinu(prices[s->order], &amount) != PC_OK) return 0;
    /* subtraction, like every other amount guard here. bounded inputs make the
       addition safe today; the shape is the point. */
    if (amount > s->ch.capacity_koinu || s->owed > s->ch.capacity_koinu - amount)
        return 0;
    if (total_out) *total_out = s->owed + amount;
    return 1;
}

/* [5] Bob prices the next order and asks for the running total. */
static int send_invoice(int fd, session *s, const char *bob_addr,
                        const char **prices, int nprices)
{
    uint64_t total = 0;
    if (!invoice_due(s, prices, nprices, &total)) return 0;
    s->owed = total;
    s->order++;

    pc_envelope out;
    memset(&out, 0, sizeof(out));
    out.type = PC_MSG_INVOICE;
    snprintf(out.ref, sizeof(out.ref), "%s", s->ch.funding_txid);
    out.to_bob_koinu = s->owed;
    snprintf(out.addr, sizeof(out.addr), "%s", bob_addr);
    snprintf(out.psbt_hex, sizeof(out.psbt_hex), "01");
    printf("invoice  order %d, %s DOGE, %" PRIu64 " total\n",
           s->order, prices[s->order - 1], s->owed);
    fflush(stdout);
    return pc_wire_send(fd, &out);
}

/* [6][G] A payment counts only once Bob has read what he signed. */
static int handle_payment(int fd, session *s, const pc_envelope *in,
                          const char *wif, int more_to_come)
{
    if (strcmp(in->ref, s->ch.funding_txid) != 0)
        return send_reject(fd, "wrong funding"), 0;
    if (in->to_bob_koinu != s->owed)
        return send_reject(fd, "not the invoiced amount"), 0;

    /* Sign first, then read it. Bob's signature never leaves this process
       until the transaction checks out, and assembling it is the only way to
       see the outpoint and the amounts. */
    char *raw = NULL;
    pc_result r = pc_payment_countersign(&s->ch, in->psbt_hex, wif, &raw);
    if (r != PC_OK) return send_reject(fd, "will not countersign"), 0;

    r = pc_tx_verify_payment(&s->ch, raw, in->to_bob_koinu);
    if (r != PC_OK) {
        dogecoin_free(raw);
        /* say which. four of these are nothing to do with the amount, and a
           customer told "pays less than it says" over a short fee has no route
           from that to the problem. */
        return send_reject(fd, pc_strerror(r)), 0;
    }

    r = pc_payment_accept(&s->ch, in->psbt_hex, in->to_bob_koinu);
    if (r != PC_OK) { dogecoin_free(raw); return send_reject(fd, "does not advance the channel"), 0; }

    if (s->best) dogecoin_free(s->best);
    s->best = raw;
    s->best_amount = in->to_bob_koinu;

    /* Durable before the ack, never after. The ack is what tells a merchant to
       ship, so a crash between the two has to cost Alice a retry rather than
       cost Bob the payment he already answered for. */
    if (pc_state_save(&s->st, &s->ch, s->best) != PC_OK)
        return send_reject(fd, "cannot record payment"), 0;
    /* "held" is not "confirmed": Bob cannot see the chain, so this is money only
       once the funding output is buried. Do not ship against this line alone. */
    printf("paid     %" PRIu64 " koinu held (%zu byte tx), "
           "unconfirmed until funding is buried\n",
           s->best_amount, strlen(s->best) / 2);
    fflush(stdout);

    pc_envelope out;
    memset(&out, 0, sizeof(out));
    out.type = PC_MSG_ACK;
    snprintf(out.ref, sizeof(out.ref), "%s", s->ch.funding_txid);
    out.to_bob_koinu = s->ch.paid_to_bob_koinu;
    /* Only Bob knows the order is finished. Alice reads this to tell a pause
       from an ending, and blocks on recv forever if it is missing. */
    out.more = more_to_come;
    snprintf(out.psbt_hex, sizeof(out.psbt_hex), "01");
    return pc_wire_send(fd, &out);
}

/* One connection, start to finish. Runs in a child, so its state is its own and
   nothing it does can touch another peer's session. */
static void serve_connection(int fd, const char *wif, pc_chain chain,
                             const char *bob_pub, const char *bob_addr,
                             uint32_t height, uint32_t slack,
                             const char *state_dir,
                             const char *height_file, unsigned height_max_age,
                             const char *confirm_cmd, unsigned min_depth,
                             const char *broadcast_cmd,
                             const char **prices, int nprices)
{
    session s;
    memset(&s, 0, sizeof(s));
    /* after the memset, not before: zeroing the struct sets the state fd to 0,
       which is a descriptor rather than the -1 that means "no state here" */
    pc_state_disable(&s.st);

    pc_envelope in, out;
    int alive = 1, opened = 0, sent = 0;
    while (alive && pc_wire_recv(fd, &in) == 1) {
        switch (in.type) {
        case PC_MSG_REQUEST:                      /* [1][2] */
            memset(&out, 0, sizeof(out));
            out.type = PC_MSG_ANNOUNCE;
            snprintf(out.psbt_hex, sizeof(out.psbt_hex), "%s", bob_pub);
            snprintf(out.addr, sizeof(out.addr), "%s", bob_addr);
            alive = pc_wire_send(fd, &out);
            break;

        case PC_MSG_OPEN:                         /* [3][4] */
            /* a second one resets the channel and the amount paid while the
               order count and the held transaction survive from the first */
            if (opened) { alive = send_reject(fd, "channel already open"); break; }
            alive = handle_open(fd, &s, &in, wif, chain, bob_pub, height, slack,
                                state_dir, height_file, height_max_age,
                                confirm_cmd, min_depth);
            if (alive) {
                opened = 1;
                if (!send_invoice(fd, &s, bob_addr, prices, nprices)) {
                    send_reject(fd, "nothing to invoice");
                    alive = 0;
                }
            }
            break;

        case PC_MSG_PAYMENT: {                    /* [6][G] */
            if (!opened) { alive = send_reject(fd, "no channel"); break; }
            int more = invoice_due(&s, prices, nprices, NULL);
            if (!more && s.order < nprices)
                fprintf(stderr, "order %d would exceed the channel\n", s.order + 1);
            alive = handle_payment(fd, &s, &in, wif, more);
            /* Not fatal when nothing more is due: Alice still has a close
               to send, and Bob has the transaction she wants back. */
            if (alive && more)
                alive = send_invoice(fd, &s, bob_addr, prices, nprices);
            break;
        }

        case PC_MSG_CLOSE:                        /* [H] */
            if (!s.best) { alive = send_reject(fd, "nothing to close on"); break; }
            /* Retire before answering, for the same reason the ratchet is saved
               before the ack: after this the channel is over, and a session
               that reopened the outpoint would be asking to be shipped against
               a transaction this one is about to broadcast. */
            if (pc_state_retire(&s.st, &s.ch, s.best) != PC_OK) {
                alive = send_reject(fd, "cannot close channel");
                break;
            }
            memset(&out, 0, sizeof(out));
            out.type = PC_MSG_CLOSE;
            snprintf(out.ref, sizeof(out.ref), "%s", s.ch.funding_txid);
            out.to_bob_koinu = s.best_amount;
            snprintf(out.psbt_hex, sizeof(out.psbt_hex), "%s", s.best);
            pc_wire_send(fd, &out);
            printf("closed   at %" PRIu64 " koinu\n", s.best_amount);

            /* Alice has been answered, so what follows is Bob's own business
               and is not inside her read budget. That is why the broadcast can
               take longer than a confirmation is allowed to. */
            if (confirm_cmd) {
                const char *why = "";
                if (funding_is_confirmed(confirm_cmd, &s.ch, 1, &why) != 1)
                    printf("WARNING  the funding output is gone: %s\n"
                           "         the transaction below cannot confirm\n", why);
            }
            if (broadcast_cmd) sent = broadcast(broadcast_cmd, s.best);
            alive = 0;
            break;

        default:
            alive = send_reject(fd, "unexpected message");
            break;
        }
    }

    if (s.best) {
        printf(sent ? "\nsent, keep this in case it needs sending again:\n%s\n\n"
                    : "\nbroadcast this to take the money:\n%s\n\n", s.best);
        fflush(stdout);
        dogecoin_free(s.best);
    }
    pc_state_close(&s.st);
}

int main(int argc, char **argv)
{
    const char *wif_arg = NULL, *listen_at = NULL;
    const char *prices[MAX_ORDERS];
    int nprices = 0;
    uint32_t height = 0, slack = 100;
    const char *state_dir = NULL, *height_file = NULL, *confirm_cmd = NULL;
    const char *broadcast_cmd = NULL;
    int sweep = 0;
    unsigned margin = 50;
    unsigned height_max_age = 600, min_depth = 6;
    int max_per_ip = DEFAULT_MAX_PER_IP;
    pc_chain chain = PC_CHAIN_MAIN;
    int want_pubkey = 0, once = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : NULL)
        if      (!strcmp(a, "--wif"))       wif_arg = NEXT();
        else if (!strcmp(a, "--listen"))    listen_at = NEXT();
        else if (!strcmp(a, "--height"))    { const char *v = NEXT(); height = v ? (uint32_t)strtoul(v, NULL, 10) : 0; }
        else if (!strcmp(a, "--state"))     { state_dir = NEXT(); }
        else if (!strcmp(a, "--height-file")) { height_file = NEXT(); }
        else if (!strcmp(a, "--confirm-cmd")) { confirm_cmd = NEXT(); }
        else if (!strcmp(a, "--broadcast-cmd")) { broadcast_cmd = NEXT(); }
        else if (!strcmp(a, "--sweep"))     { sweep = 1; }
        else if (!strcmp(a, "--sweep-margin")) { const char *v = NEXT(); margin = v ? (unsigned)strtoul(v, NULL, 10) : 0; }
        else if (!strcmp(a, "--min-depth"))  { const char *v = NEXT(); min_depth = v ? (unsigned)strtoul(v, NULL, 10) : 0; }
        else if (!strcmp(a, "--height-max-age")) { const char *v = NEXT(); height_max_age = v ? (unsigned)strtoul(v, NULL, 10) : 0; }
        else if (!strcmp(a, "--min-slack")) { const char *v = NEXT(); slack  = v ? (uint32_t)strtoul(v, NULL, 10) : 0; }
        else if (!strcmp(a, "--max-per-ip")){ const char *v = NEXT(); max_per_ip = v ? (int)strtol(v, NULL, 10) : 0; }
        else if (!strcmp(a, "--testnet"))   chain = PC_CHAIN_TEST;
        else if (!strcmp(a, "--regtest"))   chain = PC_CHAIN_REGTEST;
        else if (!strcmp(a, "--pubkey"))    want_pubkey = 1;
        else if (!strcmp(a, "--once"))      once = 1;
        else if (!strcmp(a, "--price")) {
            const char *v = NEXT();
            if (!v || nprices == MAX_ORDERS) { usage(); return 2; }
            prices[nprices++] = v;
        }
        else { usage(); return 2; }
        #undef NEXT
    }
    if (max_per_ip < 0) { usage(); return 2; }

    /* a peer that closes mid-write must not take the process with it */
    signal(SIGPIPE, SIG_IGN);

    /* A sweep signs nothing and answers nobody: it reads the directory,
       broadcasts what is about to expire, and exits. So it needs no key, which
       is why it comes before --wif is demanded: asking for one would put a key
       on a cron line for no reason. */
    if (sweep) {
        if (!state_dir || !height_file) {
            fprintf(stderr, "bob: --sweep needs --state DIR and --height-file PATH\n");
            return 2;
        }
        /* rebuilding a channel validates both pubkeys, which needs the curve
           context, so this cannot run before it is up */
        dogecoin_ecc_start();
        int srv = do_sweep(state_dir, height_file, height_max_age,
                           broadcast_cmd, confirm_cmd, min_depth, margin, chain);
        dogecoin_ecc_stop();
        return srv;
    }

    if (!wif_arg) { usage(); return 2; }

    /* Pull the key out of argv immediately, so it is not sitting in ps for the
       life of the process. */
    char *wif = pc_read_secret_arg(wif_arg);
    if (!wif) { fprintf(stderr, "bob: cannot read --wif\n"); return 2; }

    dogecoin_ecc_start();
    int rc = 1;

    char bob_pub[PUBKEYHEXLEN], bob_addr[P2PKHLEN];
    if (!pc_identity(wif, chain, bob_pub, bob_addr)) {
        fprintf(stderr, "bob: wif would not decode\n");
        goto done;
    }
    if (want_pubkey) { printf("%s\n", bob_pub); rc = 0; goto done; }
    if (nprices == 0) { usage(); goto done; }
    /* A Bob that serves more than one connection and forgets between them
       pays for goods once per reconnection: three sessions on one funding
       output each acked five DOGE and only one of those transactions can
       confirm. --once cannot replay, so it is the only configuration that is
       safe without a place to keep the ratchet. */
    if (!state_dir && !once) {
        fprintf(stderr, "bob: --state DIR is required without --once, or one "
                        "funding output pays for goods once per reconnection\n");
        return 1;
    }
    if (state_dir) {
        struct stat sb;
        if (stat(state_dir, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
            fprintf(stderr, "bob: --state %s is not a directory\n", state_dir);
            return 1;
        }
    }

    /* Same argument as --state, one field over. A number given once is correct
       once, and min-slack is checked against it at every open, so a long-lived
       Bob compares locktimes to a height as old as his uptime. --once cannot
       outlive its own number. */
    if (!height_file && !once) {
        fprintf(stderr, "bob: --height-file PATH is required without --once, or "
                        "min-slack is measured against a height that stops "
                        "being true\n");
        goto done;
    }
    if (height == 0 && !height_file) {
        fprintf(stderr, "bob: --height or --height-file is required, since the "
                        "locktime is only meaningful against a height\n");
        goto done;
    }
    if (height_file) {
        const char *why = "";
        uint32_t probe = 0;
        if (!read_height_file(height_file, height_max_age, &probe, &why)) {
            fprintf(stderr, "bob: %s: %s\n", height_file, why);
            goto done;
        }
        printf("height   %u from %s, refused when older than %us\n",
               probe, height_file, height_max_age);
    }

    char host[64] = "127.0.0.1";
    int port = PC_DEFAULT_PORT;
    if (listen_at) {
        port = pc_wire_split(listen_at, host, sizeof(host), PC_DEFAULT_PORT);
        if (port < 0) { fprintf(stderr, "bob: bad --listen\n"); goto done; }
        if (!host[0]) snprintf(host, sizeof(host), "127.0.0.1");
    }
    int lfd = pc_wire_listen(host, port);
    if (lfd < 0) { fprintf(stderr, "bob: cannot listen on %s:%d\n", host, port); goto done; }

    printf("paid to  %s\n", bob_addr);
    printf("listening on %s:%d\n\n", host, port);
    fflush(stdout);

    struct { pid_t pid; uint32_t ip; } kids[MAX_CONNS];
    int live = 0;
    do {
        uint32_t peer_ip = 0;
        int fd = pc_wire_accept(lfd, &peer_ip);
        if (fd < 0) continue;

        /* Reap finished children and reclaim their slots, then enforce the
           caps. Reaping here (not via SIG_IGN) is what keeps the counts honest,
           so the caps track connections that are actually live. */
        if (!once) {
            pid_t gone;
            while ((gone = waitpid(-1, NULL, WNOHANG)) > 0)
                for (int k = 0; k < live; k++)
                    if (kids[k].pid == gone) { kids[k] = kids[--live]; break; }
        }

        /* Global cap first: an unbounded fork-per-connection is its own denial
           of service. Then the per-source cap, so one address cannot take every
           slot. Both refuse rather than fork past the limit. */
        if (live >= MAX_CONNS) {
            send_reject(fd, "too many connections");
            close(fd);
            continue;
        }
        if (max_per_ip > 0 && peer_ip) {
            int from_ip = 0;
            for (int k = 0; k < live; k++) if (kids[k].ip == peer_ip) from_ip++;
            if (from_ip >= max_per_ip) {
                send_reject(fd, "too many from one address");
                close(fd);
                continue;
            }
        }

        pid_t pid = fork();
        if (pid < 0) { close(fd); continue; }
        if (pid == 0) {
            close(lfd);
            limit_child();
            serve_connection(fd, wif, chain, bob_pub, bob_addr,
                             height, slack, state_dir, height_file,
                             height_max_age, confirm_cmd, min_depth,
                             broadcast_cmd, prices, nprices);
            close(fd);
            _exit(0);
        }
        kids[live].pid = pid;
        kids[live].ip  = peer_ip;
        live++;
        close(fd);                 /* the child owns it now */
        if (once) { waitpid(pid, NULL, 0); break; }
    } while (1);

    close(lfd);
    rc = 0;
done:
    pc_secret_free(wif);
    dogecoin_ecc_stop();
    return rc;
}
