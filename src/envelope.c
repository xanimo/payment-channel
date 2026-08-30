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

/* The wire envelope, deliberately not a JSON library.
 *
 * Every field is a fixed shape: two short enums, a 64-character hex reference,
 * an unsigned integer, and a hex blob. A parser for that needs no allocation,
 * no nesting and no escaping, and refusing anything it does not recognise is a
 * feature rather than a limitation. A general JSON parser here would be a
 * dependency and a larger attack surface for no gain. */

#include "channel.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const struct { const char *name; size_t len; pc_msg_type t; } TYPES[] = {
    { "request",  7, PC_MSG_REQUEST  },
    { "announce", 8, PC_MSG_ANNOUNCE },
    { "open",     4, PC_MSG_OPEN     },
    { "accept",   6, PC_MSG_ACCEPT   },
    { "reject",   6, PC_MSG_REJECT   },
    { "invoice",  7, PC_MSG_INVOICE  },
    { "payment",  7, PC_MSG_PAYMENT  },
    { "ack",      3, PC_MSG_ACK      },
    { "close",    5, PC_MSG_CLOSE    },
};

static const char *type_name(pc_msg_type t)
{
    for (size_t i = 0; i < sizeof(TYPES) / sizeof(TYPES[0]); i++)
        if (TYPES[i].t == t) return TYPES[i].name;
    return NULL;
}

static int type_from_name(const char *s, size_t len, pc_msg_type *out)
{
    for (size_t i = 0; i < sizeof(TYPES) / sizeof(TYPES[0]); i++)
        if (len == TYPES[i].len && !memcmp(s, TYPES[i].name, len)) {
            *out = TYPES[i].t;
            return 1;
        }
    return 0;
}

/* base58 has no punctuation, so an address needs no escaping. A reject reason
   rides in the same field and every one of them has spaces in it, so a space is
   allowed too: held to base58's alphabet the field could not carry a reason at
   all, and every reject failed to encode rather than reaching the peer. What
   matters for a hand-rolled encoder is that neither can contain a quote or a
   backslash, and neither can. */
static int is_safe_text(const char *s)
{
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') || c == ' '))
            return 0;
    }
    return 1;
}

static int is_hex(const char *s, size_t len)
{
    if (len == 0) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

pc_result pc_envelope_encode(const pc_envelope *env, char *out, size_t cap)
{
    if (!env || !out) return PC_ERR_ARG;
    const char *t = type_name(env->type);
    if (!t) return PC_ERR_ARG;
    if (env->ref[0] && (strlen(env->ref) != 64 || !is_hex(env->ref, 64)))
        return PC_ERR_ARG;
    if (env->psbt_hex[0] && !is_hex(env->psbt_hex, strlen(env->psbt_hex)))
        return PC_ERR_ARG;
    if (env->tx_hex[0] && !is_hex(env->tx_hex, strlen(env->tx_hex)))
        return PC_ERR_ARG;
    if (env->addr[0] && !is_safe_text(env->addr)) return PC_ERR_ARG;
    if (env->vout < 0) return PC_ERR_ARG;
    if (env->more != 0 && env->more != 1) return PC_ERR_ARG;

    int n = snprintf(out, cap,
                     "{\"type\":\"%s\",\"ref\":\"%s\",\"vout\":%d,\"more\":%d"
                     ",\"to_bob\":%" PRIu64 ",\"addr\":\"%s\""
                     ",\"psbt\":\"%s\",\"tx\":\"%s\"}",
                     t, env->ref, env->vout, env->more, env->to_bob_koinu,
                     env->addr, env->psbt_hex, env->tx_hex);
    if (n < 0 || (size_t)n >= cap) return PC_ERR_ARG;
    return PC_OK;
}

/* Find "key":  and return a pointer just past the colon, or NULL. */
static const char *find_key(const char *json, const char *key)
{
    char pat[32];
    int n = snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (n < 0 || (size_t)n >= sizeof(pat)) return NULL;
    const char *p = strstr(json, pat);
    if (!p) return NULL;
    p += (size_t)n;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

/* Read a quoted string value into (dst). No escape handling: every field this
 * protocol carries is hex or a short keyword, so a backslash is malformed. */
static int read_string(const char *p, char *dst, size_t cap, size_t *len_out)
{
    if (!p || *p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"') {
        if (*p == '\\') return 0;
        if (i + 1 >= cap) return 0;
        dst[i++] = *p++;
    }
    if (*p != '"') return 0;
    dst[i] = '\0';
    if (len_out) *len_out = i;
    return 1;
}

/* A repeated key is two answers to one question and find_key() takes the first,
   so the second would be ignored rather than noticed. No value can contain a
   quote, so a quoted key only ever appears as a key. */
static int has_duplicate_key(const char *json)
{
    static const char *KEYS[] = { "type", "ref", "vout", "more",
                                  "to_bob", "addr", "psbt", "tx" };
    for (size_t i = 0; i < sizeof(KEYS) / sizeof(KEYS[0]); i++) {
        char pat[32];
        int n = snprintf(pat, sizeof(pat), "\"%s\"", KEYS[i]);
        if (n < 0 || (size_t)n >= sizeof(pat)) return 1;
        const char *p = strstr(json, pat);
        if (p && strstr(p + n, pat)) return 1;
    }
    return 0;
}

pc_result pc_envelope_decode(const char *json, pc_envelope *env)
{
    if (!json || !env) return PC_ERR_ARG;
    memset(env, 0, sizeof(*env));
    if (has_duplicate_key(json)) return PC_ERR_ARG;

    char tbuf[16];
    size_t tlen = 0;
    if (!read_string(find_key(json, "type"), tbuf, sizeof(tbuf), &tlen))
        return PC_ERR_ARG;
    if (!type_from_name(tbuf, tlen, &env->type)) return PC_ERR_ARG;

    /* ref is empty on an announce, since the channel has no id until funded */
    const char *rp = find_key(json, "ref");
    if (rp) {
        size_t rlen = 0;
        if (!read_string(rp, env->ref, sizeof(env->ref), &rlen)) return PC_ERR_ARG;
        if (rlen && (rlen != 64 || !is_hex(env->ref, rlen))) return PC_ERR_ARG;
    }

    const char *ap = find_key(json, "to_bob");
    if (ap) {
        /* strtoull negates a leading minus and reports success, so "-1" would
           arrive as UINT64_MAX and walk through every amount guard downstream */
        if (*ap == '-' || *ap == '+') return PC_ERR_ARG;
        errno = 0;
        char *end = NULL;
        unsigned long long v = strtoull(ap, &end, 10);
        if (end == ap || errno == ERANGE) return PC_ERR_ARG;
        if (*end != ',' && *end != '}') return PC_ERR_ARG;
        env->to_bob_koinu = (uint64_t)v;
    }

    const char *vp = find_key(json, "vout");
    if (vp) {
        errno = 0;
        char *end = NULL;
        long v = strtol(vp, &end, 10);
        if (end == vp || errno == ERANGE || v < 0 || v > 0xFFFF) return PC_ERR_ARG;
        if (*end != ',' && *end != '}') return PC_ERR_ARG;
        env->vout = (int)v;
    }

    /* absent means no, so a peer that predates the field still parses */
    const char *mp = find_key(json, "more");
    if (mp) {
        char *end = NULL;
        long v = strtol(mp, &end, 10);
        if (end == mp || (v != 0 && v != 1)) return PC_ERR_ARG;
        if (*end != ',' && *end != '}') return PC_ERR_ARG;
        env->more = (int)v;
    }

    const char *dp = find_key(json, "addr");
    if (dp) {
        if (!read_string(dp, env->addr, sizeof(env->addr), NULL)) return PC_ERR_ARG;
        if (!is_safe_text(env->addr)) return PC_ERR_ARG;
    }

    size_t plen = 0;
    if (!read_string(find_key(json, "psbt"), env->psbt_hex,
                     sizeof(env->psbt_hex), &plen))
        return PC_ERR_ARG;
    if (plen && !is_hex(env->psbt_hex, plen)) return PC_ERR_ARG;

    const char *xp = find_key(json, "tx");
    if (xp) {
        size_t xlen = 0;
        if (!read_string(xp, env->tx_hex, sizeof(env->tx_hex), &xlen))
            return PC_ERR_ARG;
        if (xlen && !is_hex(env->tx_hex, xlen)) return PC_ERR_ARG;
    }

    /* the types that carry money must actually carry it */
    if ((env->type == PC_MSG_PAYMENT || env->type == PC_MSG_OPEN ||
         env->type == PC_MSG_CLOSE) && !env->psbt_hex[0])
        return PC_ERR_ARG;

    return PC_OK;
}
