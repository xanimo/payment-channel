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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *type_name(pc_msg_type t)
{
    switch (t) {
    case PC_MSG_ANNOUNCE: return "announce";
    case PC_MSG_PAYMENT:  return "payment";
    case PC_MSG_ACK:      return "ack";
    case PC_MSG_CLOSE:    return "close";
    }
    return NULL;
}

static int type_from_name(const char *s, size_t len, pc_msg_type *out)
{
    if (len == 8 && !memcmp(s, "announce", 8)) { *out = PC_MSG_ANNOUNCE; return 1; }
    if (len == 7 && !memcmp(s, "payment",  7)) { *out = PC_MSG_PAYMENT;  return 1; }
    if (len == 3 && !memcmp(s, "ack",      3)) { *out = PC_MSG_ACK;      return 1; }
    if (len == 5 && !memcmp(s, "close",    5)) { *out = PC_MSG_CLOSE;    return 1; }
    return 0;
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
    if (!is_hex(env->psbt_hex, strlen(env->psbt_hex))) return PC_ERR_ARG;

    int n = snprintf(out, cap,
                     "{\"type\":\"%s\",\"ref\":\"%s\",\"to_bob\":%" PRIu64
                     ",\"psbt\":\"%s\"}",
                     t, env->ref, env->to_bob_koinu, env->psbt_hex);
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

pc_result pc_envelope_decode(const char *json, pc_envelope *env)
{
    if (!json || !env) return PC_ERR_ARG;
    memset(env, 0, sizeof(*env));

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
        char *end = NULL;
        unsigned long long v = strtoull(ap, &end, 10);
        if (end == ap) return PC_ERR_ARG;
        env->to_bob_koinu = (uint64_t)v;
    }

    size_t plen = 0;
    if (!read_string(find_key(json, "psbt"), env->psbt_hex,
                     sizeof(env->psbt_hex), &plen))
        return PC_ERR_ARG;
    if (!is_hex(env->psbt_hex, plen)) return PC_ERR_ARG;

    return PC_OK;
}
