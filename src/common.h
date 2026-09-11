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

/* Bits both programs need and neither should own. */

#ifndef PAYMENT_CHANNEL_COMMON_H
#define PAYMENT_CHANNEL_COMMON_H

#include "channel.h"
#include "wire.h"
#include "hex.h"
#include "ec.h"
#include "address.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PC_DEFAULT_PORT 9876

/* Bound on a backend command's own arguments, before the two appended. */
#define PC_BACKEND_MAX_ARGV 32

/* Wipe key material through a volatile pointer so the clear is not optimized
   away. */
static inline void pc_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

/* Derive the compressed pubkey hex and the p2pkh address a WIF key controls. */
static inline int pc_identity(const char *wif, pc_chain which,
                       char pubkey_hex[PUBKEYHEXLEN], char addr[P2PKHLEN])
{
    const kw_chainparams *cp = pc_chainparams(which);

    uint8_t sk[32], pub[33];
    int compressed = 0;
    uint8_t ver = 0;
    if (!kw_wif_decode(wif, sk, &compressed, &ver) || ver != cp->wif) {
        pc_wipe(sk, sizeof sk);
        return 0;
    }
    int ok = kw_ec_pubkey(sk, pub);
    pc_wipe(sk, sizeof sk);
    if (!ok) return 0;

    pc_bin_to_hex(pub, 33, pubkey_hex);
    return kw_address_p2pkh(pub, cp->p2pkh, addr, P2PKHLEN) ? 1 : 0;
}

/* Derive the p2pkh address a compressed pubkey controls, no private key. This is
   how a Bob that delegates signing knows its own identity: it is given the public
   key (safe to hold) while the key stays in the signer. */
static inline int pc_identity_pub(const char *pubkey_hex, pc_chain which,
                                  char addr[P2PKHLEN])
{
    uint8_t raw[33], pub[33];
    if (strlen(pubkey_hex) != 66 || !pc_hex_to_bin(pubkey_hex, raw, 33)) return 0;
    if (!kw_ec_pubkey_parse(raw, 33, pub)) return 0;   /* rejects a non-point */
    return kw_address_p2pkh(pub, pc_chainparams(which)->p2pkh, addr, P2PKHLEN) ? 1 : 0;
}

/* "txid:vout" */
static inline int pc_split_outpoint(const char *s, char txid[65], int *vout)
{
    const char *colon = strchr(s, ':');
    if (!colon || (size_t)(colon - s) != 64) return 0;
    memcpy(txid, s, 64);
    txid[64] = '\0';
    for (size_t i = 0; i < 64; i++)
        if (!isxdigit((unsigned char)txid[i])) return 0;
    char *end = NULL;
    long v = strtol(colon + 1, &end, 10);
    if (end == colon + 1 || *end || v < 0 || v > 0xFFFF) return 0;
    *vout = (int)v;
    return 1;
}

/* Split a backend command into argv, in place.
 *
 * The backends take their own arguments (kw outpoint needs --node), so this
 * cannot be a bare path, and splitting on spaces alone means a path containing
 * one cannot be given at all. Quotes and backslash fix that and nothing else:
 * there is no expansion, no globbing, no operators and no shell, and the result
 * goes straight to execvp.
 *
 * Returns the count, or -1 for an unterminated quote, a trailing backslash, or
 * more than (max) tokens. (buf) is modified and (argv) points into it.
 */
static inline int pc_split_argv(char *buf, char **argv, size_t max)
{
    size_t argc = 0;
    char *r = buf, *w = buf;

    while (*r) {
        while (*r == ' ' || *r == '\t') r++;
        if (!*r) break;
        if (argc >= max) return -1;
        argv[argc++] = w;

        while (*r && *r != ' ' && *r != '\t') {
            if (*r == '\\') {
                if (!*++r) return -1;            /* nothing to escape */
                *w++ = *r++;
            } else if (*r == '\'') {             /* literal, as a shell's */
                r++;
                while (*r != '\'') { if (!*r) return -1; *w++ = *r++; }
                r++;
            } else if (*r == '"') {
                r++;
                while (*r != '"') {
                    if (!*r) return -1;
                    if (*r == '\\' && r[1]) r++;
                    *w++ = *r++;
                }
                r++;
            } else {
                *w++ = *r++;
            }
        }
        /* Step past the delimiter before terminating the token. Quoting only
           ever removes characters, so w <= r, and writing the NUL first would
           clobber the very byte r is standing on when they are equal. */
        int done = (*r == '\0');
        if (!done) r++;
        *w++ = '\0';
        if (done) break;
    }
    return (int)argc;
}

/* Run (cmd), split into argv by pc_split_argv, with (extra) appended and (feed)
   written to its stdin, and killed after (seconds).
 *
 * Every backend goes through this: the confirmation, the broadcast, the signer,
 * the replica and Alice's feerate. They differ in their arguments and their
 * budget and in nothing else. One runner is the point rather than a
 * convenience: a second one grows its own idea of how a command splits, and
 * then a path that works for one backend does not work for another.
 *
 * Never a shell. No expansion, no globbing, no operators, and a command that
 * does not fit the buffer fails the exec rather than running a truncated one.
 * Returns 0 if it could not be run or did not answer in time. */
static inline int pc_run_backend(const char *cmd, const char *const *extra, size_t nextra,
                       const char *feed, unsigned seconds,
                       char *out, size_t cap, int *status)
{
    int fds[2], in[2];
    if (pipe(fds) != 0) return 0;
    if (pipe(in) != 0) { close(fds[0]); close(fds[1]); return 0; }

    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); close(in[0]); close(in[1]); return 0; }
    if (pid == 0) {
        /* Its own process group, so the timeout below can kill what the
           backend started as well as the backend. A wrapper script that execs
           nothing and waits on a child would otherwise survive being killed,
           keep the inherited stderr open, and outlive the caller. */
        setpgid(0, 0);
        close(fds[0]); close(in[1]);
        dup2(fds[1], STDOUT_FILENO);
        dup2(in[0], STDIN_FILENO);
        close(fds[1]); close(in[0]);

        /* Quotes and backslash are honoured so a backend path may contain a
           space; see pc_split_argv. It is still not a shell. The split is over
           the operator's own argument, and the values appended after it are a
           validated address and a validated outpoint, so nothing off the wire
           reaches argv unchecked. */
        char *argv[PC_BACKEND_MAX_ARGV];
        char split[512];
        /* Truncation would silently drop the tail of the last token, turning
           --node host:22556 into --node host:2. Fail the exec instead. */
        if (snprintf(split, sizeof(split), "%s", cmd) >= (int)sizeof(split)) _exit(127);
        if (nextra + 1 >= PC_BACKEND_MAX_ARGV) _exit(127);   /* no room to append */
        int argc = pc_split_argv(split, argv, PC_BACKEND_MAX_ARGV - nextra - 1);
        if (argc <= 0) _exit(127);
        size_t ac = (size_t)argc;
        for (size_t i = 0; i < nextra; i++) argv[ac++] = (char *)extra[i];
        argv[ac] = NULL;
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

    int st = 0;
    if (!timed_out) {
        /* The read loop also ends on EOF, and a backend can close stdout while
           it keeps running. Bound the reap by the same deadline so that cannot
           hang the caller past its budget. */
        for (;;) {
            pid_t w = waitpid(pid, &st, WNOHANG);
            if (w == pid) break;
            if (w < 0 && errno != EINTR) { timed_out = 1; break; }
            if (time(NULL) >= deadline) { timed_out = 1; break; }
            poll(NULL, 0, 20);          /* 20ms, nothing to wait on but the clock */
        }
    }
    if (timed_out) {
        /* The group first, then the leader in case setpgid lost the race with
           the exec. Killing only the leader leaves its children running. */
        kill(-pid, SIGKILL);
        kill(pid, SIGKILL);
        while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
        return 0;
    }
    *status = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    return 1;
}


/* A hex argument, or @path to read it from a file. */
static inline char *pc_read_hex_arg(const char *arg)
{
    if (arg[0] != '@') {
        char *copy = strdup(arg);
        return copy;
    }
    FILE *f = fopen(arg + 1, "r");
    if (!f) return NULL;
    size_t cap = 65536, n = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { fclose(f); return NULL; }
    int c;
    while ((c = fgetc(f)) != EOF) {
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        if (n + 1 >= cap) { fclose(f); free(buf); return NULL; }
        buf[n++] = (char)c;
    }
    fclose(f);
    buf[n] = '\0';
    return buf;
}

/* Load a secret (a WIF) without leaving it in argv, where ps and the shell
   history expose it to any local user. "@path" reads one line from a file, which
   should be mode 0600; "-" reads one line from stdin. A bare value still works
   for the tests, but it is the insecure form and the docs say so. Caller frees
   with pc_secret_free(), which wipes the copy first. */
/* Pin a secret in RAM so it is never written to swap, which is the plaintext
   copy of the key custody is supposed to prevent. Best effort but loud: mlock
   fails under a low RLIMIT_MEMLOCK, and an operator who is one page short of
   locking their key should hear it rather than believe it is protected. */
static inline char *pc_secret_harden(char *s)
{
    if (!s) return NULL;
    if (mlock(s, strlen(s) + 1) != 0)
        fprintf(stderr, "warning: mlock of secret failed (%s): "
                        "the key may reach swap\n", strerror(errno));
    return s;
}

static inline char *pc_read_secret_arg(const char *arg)
{
    if (!arg) return NULL;
    FILE *f = NULL;
    int owned = 0;
    if (!strcmp(arg, "-")) {
        f = stdin;
    } else if (arg[0] == '@') {
        f = fopen(arg + 1, "r");
        if (!f) return NULL;
        owned = 1;
    } else {
        return pc_secret_harden(strdup(arg));
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n = getline(&line, &cap, f);
    if (owned) fclose(f);
    if (n < 0) { free(line); return NULL; }
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r' ||
                     line[n - 1] == ' '  || line[n - 1] == '\t'))
        line[--n] = '\0';
    if (n == 0) { free(line); return NULL; }
    return pc_secret_harden(line);
}

/* Wipe through a volatile pointer so the clear is not optimized away, then free.
   Only the string itself is wiped; getline may have over-allocated, but the
   secret ends at the NUL. */
static inline void pc_secret_free(char *s)
{
    if (!s) return;
    size_t n = strlen(s);
    volatile char *p = (volatile char *)s;
    size_t k = n;
    while (k--) *p++ = 0;
    munlock(s, n + 1);              /* wipe first, then release the lock */
    free(s);
}

static inline void pc_announce(pc_envelope *env, const char *pubkey_hex, uint32_t locktime)
{
    memset(env, 0, sizeof(*env));
    env->type = PC_MSG_ANNOUNCE;
    env->to_bob_koinu = locktime;
    snprintf(env->psbt_hex, sizeof(env->psbt_hex), "%s", pubkey_hex);
}

#endif /* PAYMENT_CHANNEL_COMMON_H */
