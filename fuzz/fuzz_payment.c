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

/* The signing paths, on a PSBT off the wire.
 *
 * pc_payment_countersign() is the one place Bob's key touches something Alice
 * sent. It signs before it validates, extracts partial signatures and their
 * pubkeys into fixed buffers, hexes those, and assembles a scriptSig by hand
 * from lengths the PSBT chose. pc_payment_accept() reads the same bytes to
 * decide whether the channel advances. Neither had been fuzzed: fuzz_opening
 * reaches pc_channel_open_accept and stops there.
 *
 * The input is the PSBT hex directly, so the parser and everything downstream
 * of it sees attacker bytes. pc_payment_create() is driven from the same input
 * as a funding transaction, since Alice parses one she was given. */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "channel.h"

/* Fixed, and generated together with the corpus by fuzz/mkseed. Random keys
   per run make a seed useless: Bob cannot sign a PSBT built for a channel he is
   not in, so the assembly this exists to reach never runs. mkseed prints these
   and the PSBT at the same time for that reason. */
static const char *ALICE_PUB  =
    "034efba1e45339680661ce0d202d97b57900f019da9d0c9714bb65ccfec2577fc4";
static const char *BOB_PUB    =
    "02e1e3173654218e0cce7efe2b71297327a3ec50df8a81e8b122308feb5cc66e39";
static const char *ALICE_WIF  = "QVoxykwCdNmNg5PfgcfzShzb1PayuxkxRmp2mJN19TsJoUwzSUKX";
static const char *BOB_WIF    = "QUXyEtndDXVaHfkzDgUBAUGuxEaycFwnsC3NhRd7QfcNDuZmyaju";
static const char *ALICE_ADDR = "DThKmBaVVCZoAh6qd4gk6AF2NBPz8YTnVN";
static const char *BOB_ADDR   = "DFrvSiowA65VLpTifuNZRinHis2yD4yVUK";
static const char *FUNDING_TXID =
    "b7b25e063ca8dcd0f7fc4e3c13b91874c6698ebc9f9d366fa33cd8de438a576e";

static int ready = 0;
static pc_channel base;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void setup(void)
{
    dogecoin_ecc_start();
    if (pc_channel_init(&base, ALICE_PUB, BOB_PUB, 300000, PC_CHAIN_MAIN) != PC_OK)
        abort();
    if (pc_channel_set_funding(&base, FUNDING_TXID, 0, 10000000000ULL) != PC_OK)
        abort();
    ready = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!ready) setup();
    if (size < 2 || size > 64 * 1024) return 0;

    /* hex text, the way it arrives in the envelope, so a seed is the PSBT
       itself rather than something that has to survive being re-encoded */
    char *hex = (char *)malloc(size + 1);
    if (!hex) return 0;
    memcpy(hex, data, size);
    hex[size] = '\0';

    uint64_t claimed = ((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48) |
                       (uint64_t)size;

    /* Bob's side, which is where the attacker bytes actually arrive. The
       channel is copied because accept() advances paid_to_bob on success and
       one run must not decide what the next one is allowed to send. */
    {
        pc_channel ch = base;
        char *raw = NULL;
        if (pc_payment_countersign(&ch, hex, BOB_WIF, &raw) == PC_OK) {
            /* A countersigned transaction has to survive being read back. This
               is the ordering bob.c relies on: it signs, then verifies, and a
               transaction it will not verify must not be one this returned
               without a scriptSig it can parse. */
            if (!raw) abort();
            size_t rl = strlen(raw);
            if (rl == 0 || (rl % 2)) abort();
            dogecoin_free(raw);
        } else if (raw) {
            abort();   /* a refusal must not leave Bob holding a transaction */
        }
    }

    {
        pc_channel ch = base;
        uint64_t before = ch.paid_to_bob_koinu;
        if (pc_payment_accept(&ch, hex, claimed) == PC_OK) {
            /* the ratchet only ever moves up, and only to what was claimed */
            if (ch.paid_to_bob_koinu != claimed) abort();
            if (ch.paid_to_bob_koinu <= before) abort();
            if (ch.paid_to_bob_koinu > ch.capacity_koinu) abort();
        } else if (ch.paid_to_bob_koinu != before) {
            abort();   /* a refused payment must not have advanced anything */
        }
    }

    /* Alice's side: the funding transaction she is handed is parsed here. */
    {
        char *psbt = NULL;
        if (pc_payment_create(&base, hex, ALICE_WIF, ALICE_ADDR, BOB_ADDR,
                              1000000000ULL, 100000000ULL, &psbt) == PC_OK) {
            if (!psbt) abort();
            dogecoin_free(psbt);
        } else if (psbt) {
            abort();
        }
    }

    {
        char txid[65] = {0};
        int vout = 0;
        uint64_t value = 0;
        pc_tx_find_channel_output(&base, hex, txid, &vout, &value);
    }

    free(hex);
    return 0;
}
