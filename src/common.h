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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PC_DEFAULT_PORT 9876

/* Derive the compressed pubkey hex and the p2pkh address a WIF key controls. */
static inline int pc_identity(const char *wif, pc_chain which,
                       char pubkey_hex[PUBKEYHEXLEN], char addr[P2PKHLEN])
{
    const dogecoin_chainparams *chain = pc_chainparams(which);

    dogecoin_key key;
    dogecoin_privkey_init(&key);
    if (!dogecoin_privkey_decode_wif((char *)wif, chain, &key)) return 0;

    dogecoin_pubkey pub;
    dogecoin_pubkey_init(&pub);
    pub.compressed = true;
    dogecoin_pubkey_from_key(&key, &pub);
    dogecoin_privkey_cleanse(&key);

    if (!pub.compressed) return 0;
    utils_bin_to_hex(pub.pubkey, 33, pubkey_hex);
    if (!dogecoin_pubkey_getaddr_p2pkh(&pub, chain, addr)) return 0;
    return 1;
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
        return strdup(arg);
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
    return line;
}

/* Wipe through a volatile pointer so the clear is not optimized away, then free.
   Only the string itself is wiped; getline may have over-allocated, but the
   secret ends at the NUL. */
static inline void pc_secret_free(char *s)
{
    if (!s) return;
    volatile char *p = (volatile char *)s;
    size_t n = strlen(s);
    while (n--) *p++ = 0;
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
