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

/* Hex that reports what it did.
 *
 * utils_hex_to_bin() is the shipped converter and it is the one this program is
 * supposed to use, but it cannot be asked whether a conversion worked. It runs
 * inLen/2 iterations over the pointer it is given without consulting the NUL,
 * a character outside [0-9a-fA-F] fails all three range tests and leaves the
 * nibble as the zero it was pre-set to, and the out-count it reports is
 * assigned inLen/2 unconditionally at the end. So it converts a short string by
 * reading past it, converts a non-hex string to zeros, and reports success for
 * both. Every "did it write the length I expected" check against it is testing
 * the constant the caller passed in.
 *
 * These do the length and the alphabet first and convert only what passed. */

#ifndef PAYMENT_CHANNEL_HEX_H
#define PAYMENT_CHANNEL_HEX_H

#include <stddef.h>
#include <string.h>

static inline int pc_is_hex(const char *s, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

/* Convert exactly (nbytes) bytes, or refuse. The string has to be that long,
   no longer, and hex the whole way. */
static inline int pc_hex_to_bin(const char *hex, unsigned char *out, size_t nbytes)
{
    if (!hex || !out) return 0;
    if (strlen(hex) != nbytes * 2) return 0;
    if (!pc_is_hex(hex, nbytes * 2)) return 0;
    for (size_t i = 0; i < nbytes; i++) {
        unsigned char v = 0;
        for (int k = 0; k < 2; k++) {
            char c = hex[i * 2 + k];
            unsigned char d = (unsigned char)(c <= '9' ? c - '0'
                                            : (c | 0x20) - 'a' + 10);
            v = (unsigned char)((v << 4) | d);
        }
        out[i] = v;
    }
    return 1;
}

#endif /* PAYMENT_CHANNEL_HEX_H */
