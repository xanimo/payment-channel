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

/* The transaction reader in src/txcheck.c, on peer-supplied hex.
 *
 * Bob countersigns before he parses, so the bytes reaching this reader are
 * whatever Alice sent, assembled with a signature of his own on the front. It
 * walks varints, script lengths and output counts by hand because dogecoin_tx
 * is opaque in the installed header. Every bound in it has been read and holds;
 * that is exactly the claim worth checking mechanically rather than by eye.
 *
 * The channel is fixed so the fuzzer varies only the transaction. */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "channel.h"

static int ready = 0;
static pc_channel ch;

/* two fixed compressed keys, so the harness is deterministic and needs no
   keygen per input */
static const char *ALICE_PUB =
    "0211485fec5321a333bbb350f50c2c71cc149d4e8ec61cc525fa76d968df4daa6b";
static const char *BOB_PUB =
    "0318b32845384410357f8a241df6834c3ecb2cd399eefc8cb4f59f315ca3b24b74";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void setup(void)
{
    dogecoin_ecc_start();
    if (pc_channel_init(&ch, ALICE_PUB, BOB_PUB, 300000, PC_CHAIN_MAIN) != PC_OK)
        abort();
    /* a funding outpoint, so the reader gets past its state guard and reaches
       the parsing it is here to exercise */
    if (pc_channel_set_funding(&ch,
            "d9eda69119c8b4f9480be1d6bc4bd9d8b6969262df9a87be515261a9d3d52e77",
            0, 10000000000ULL) != PC_OK)
        abort();
    ready = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!ready) setup();

    /* the reader takes hex, which is what arrives in the envelope */
    if (size > 64 * 1024) return 0;
    char *hex = (char *)malloc(size + 1);
    if (!hex) return 0;
    memcpy(hex, data, size);
    hex[size] = '\0';

    pc_tx_verify_payment(&ch, hex, 1000000000ULL);
    pc_tx_find_channel_output(&ch, hex, NULL, NULL, NULL);

    unsigned char digest[32];
    unsigned char script[4] = { 0x51, 0x21, 0x00, 0xae };
    pc_tx_sighash(hex, script, sizeof(script), digest);

    free(hex);
    return 0;
}
