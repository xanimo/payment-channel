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

/* pc_refund_create() on a channel it was not handed by a constructor.
 *
 * The refund serializes a transaction by hand, assembles a scriptSig by hand,
 * and then parses the result back to check the assembly. Three hand-rolled
 * walks over lengths that come out of a pc_channel the caller owns. Nothing
 * fuzzed any of them: fuzz_opening reaches pc_channel_open_accept, and
 * attack.c drives this with two channels built by hand.
 *
 * A pc_channel is a public struct, so a caller can present one no constructor
 * would produce. That is the input here: the fixed fields come from a real
 * keypair so signing works, and the fuzzer owns redeem_script_hex,
 * funding_txid, locktime, capacity and the fee. The redeem script length is
 * what drives the scriptSig varint, which is where the parse has its widest
 * range of shapes. */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "channel.h"

static int ready = 0;
static char awif[PRIVKEYWIFLEN], aaddr[P2PKHLEN];
static char apub[PUBKEYHEXLEN], bpub[PUBKEYHEXLEN];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void setup(void)
{
    dogecoin_ecc_start();
    char bwif[PRIVKEYWIFLEN], baddr[P2PKHLEN];
    if (!generatePrivPubKeypair(awif, aaddr, false)) abort();
    if (!generatePrivPubKeypair(bwif, baddr, false)) abort();
    size_t n = sizeof(apub);
    if (!getPubkeyFromPrivkey(awif, false, apub, &n)) abort();
    n = sizeof(bpub);
    if (!getPubkeyFromPrivkey(bwif, false, bpub, &n)) abort();
    ready = 1;
}

static void put_hex(char *dst, size_t cap, const uint8_t *src, size_t n)
{
    static const char H[] = "0123456789abcdef";
    size_t i = 0;
    for (; i < n && i * 2 + 2 < cap; i++) {
        dst[i * 2]     = H[src[i] >> 4];
        dst[i * 2 + 1] = H[src[i] & 0x0f];
    }
    dst[i * 2] = '\0';
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!ready) setup();
    if (size < 16) return 0;

    pc_channel ch;
    if (pc_channel_init(&ch, apub, bpub, 300000, PC_CHAIN_MAIN) != PC_OK) return 0;

    /* the fee and the capacity, from the first eight bytes */
    uint64_t cap = 0, fee = 0;
    for (int i = 0; i < 4; i++) cap = (cap << 8) | data[i];
    for (int i = 4; i < 8; i++) fee = (fee << 8) | data[i];
    cap = (cap % 100000000000ULL) + 1;
    fee = (fee % 10000000ULL) + 1;
    pc_channel_set_funding(&ch,
        "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074", 0, cap);

    ch.locktime = ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) |
                  ((uint32_t)data[10] << 8) | data[11];

    /* The struct fields a constructor would have filled. The txid is left as a
       real one about half the time so the path past it stays reachable. */
    if (data[12] & 1)
        put_hex(ch.funding_txid, sizeof(ch.funding_txid), data + 13,
                (size - 13) < 32 ? (size - 13) : 32);

    /* the length that drives the scriptSig varint, and so the parse */
    put_hex(ch.redeem_script_hex, sizeof(ch.redeem_script_hex),
            data + 13, size - 13);

    char *raw = NULL;
    if (pc_refund_create(&ch, awif, aaddr, fee, &raw) == PC_OK) {
        /* Anything it returns has already been walked by its own check. This
           asserts the one property that check is for: a refund it calls OK
           carries the channel's script, so an accepted transaction is one that
           can actually spend the funding output. */
        if (!raw) abort();
        size_t rl = strlen(raw);
        if (rl == 0 || (rl % 2)) abort();
        if (ch.redeem_script_hex[0] && !strstr(raw, ch.redeem_script_hex)) abort();
        dogecoin_free(raw);
    } else if (raw) {
        abort();   /* a refusal must not leave the caller holding a transaction */
    }
    return 0;
}
