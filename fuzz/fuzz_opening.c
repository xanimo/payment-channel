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

/* The opening, on attacker bytes.
 *
 * Bob learns the whole channel from what Alice sends at open: he parses her
 * redeem script with pc_redeem_parse(), rebuilds it from the parts, and accepts
 * the channel if the two match. That parser walks a length prefix and three
 * 33-byte pushes by hand, and pc_channel_open_accept() then reads a PSBT
 * straight off the wire. Neither had been fuzzed — only the payment reader in
 * txcheck.c was.
 *
 * The input is split: the first byte picks how much of it becomes the redeem
 * script hex, the rest becomes the PSBT hex, so one corpus drives both. */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "channel.h"

static int ready = 0;
static char apub[PUBKEYHEXLEN], bpub[PUBKEYHEXLEN];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void setup(void)
{
    dogecoin_ecc_start();
    char awif[PRIVKEYWIFLEN], aaddr[P2PKHLEN];
    char bwif[PRIVKEYWIFLEN], baddr[P2PKHLEN];
    if (!generatePrivPubKeypair(awif, aaddr, false)) abort();
    if (!generatePrivPubKeypair(bwif, baddr, false)) abort();
    size_t n = sizeof(apub);
    if (!getPubkeyFromPrivkey(awif, false, apub, &n)) abort();
    n = sizeof(bpub);
    if (!getPubkeyFromPrivkey(bwif, false, bpub, &n)) abort();
    ready = 1;
}

/* hex, so the parsers get something they can at least start on */
static char *as_hex(const uint8_t *d, size_t n)
{
    char *s = (char *)malloc(n * 2 + 1);
    if (!s) return NULL;
    for (size_t i = 0; i < n; i++) {
        static const char H[] = "0123456789abcdef";
        s[i * 2]     = H[d[i] >> 4];
        s[i * 2 + 1] = H[d[i] & 0x0f];
    }
    s[n * 2] = '\0';
    return s;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!ready) setup();
    if (size < 2 || size > 32 * 1024) return 0;

    /* first byte splits the input between the two parsers */
    size_t split = 1 + ((size_t)data[0] * (size - 1)) / 256;
    if (split >= size) split = size - 1;

    char *script_hex = as_hex(data + 1, split - 1 ? split - 1 : 1);
    char *psbt_hex   = as_hex(data + split, size - split);

    if (script_hex) {
        /* the hand-rolled script walker, on raw bytes */
        char pa[PUBKEYHEXLEN], pb[PUBKEYHEXLEN];
        uint32_t lt = 0;
        if (pc_redeem_parse(script_hex, pa, pb, &lt) == PC_OK) {
            /* Anything it accepts, Bob rebuilds and compares. A script that
               parses but rebuilds to something else is the case that must be
               refused later, not one that may crash here. */
            pc_channel ch;
            if (pc_channel_init(&ch, pa, pb, lt, PC_CHAIN_MAIN) == PC_OK && psbt_hex) {
                uint64_t cap = 0;
                pc_channel_open_accept(&ch, psbt_hex, psbt_hex, 1000, 100, &cap);
            }
        }
    }

    /* and the opening acceptance against a well-formed channel, so the PSBT
       path is reached even when the script half is garbage */
    if (psbt_hex) {
        pc_channel ch;
        if (pc_channel_init(&ch, apub, bpub, 300000, PC_CHAIN_MAIN) == PC_OK) {
            uint64_t cap = 0;
            pc_channel_open_accept(&ch, psbt_hex, psbt_hex, 1000, 100, &cap);
            char txid[65] = {0};
            int vout = 0;
            uint64_t value = 0;
            pc_tx_find_channel_output(&ch, psbt_hex, txid, &vout, &value);
        }
    }

    free(script_hex);
    free(psbt_hex);
    return 0;
}
