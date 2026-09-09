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
#include <sys/mman.h>

#define PC_DEFAULT_PORT 9876

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
