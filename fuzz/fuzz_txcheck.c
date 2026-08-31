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
    "03199a3c0690b04deef10fd11946eab6082729ad96f4a5f2a76bf0f20bd721dab7";
static const char *BOB_PUB =
    "039655edd029af90333a96c8da354e33a932b860c9d6c2f3588e6235e7f8d10a77";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void setup(void)
{
    dogecoin_ecc_start();
    if (pc_channel_init(&ch, ALICE_PUB, BOB_PUB, 300000, PC_CHAIN_MAIN) != PC_OK)
        abort();
    /* a funding outpoint, so the reader gets past its state guard and reaches
       the parsing it is here to exercise */
    if (pc_channel_set_funding(&ch,
            "91ef9c45881a64dc29c8e52fd335b410e8ac318c292fb56a191693d5dcb544b9",
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

    /* Take the script code length from the input as well. A fixed four bytes
       only ever exercises put_varint's single byte branch, and verify_sigs
       passes redeem scripts up to 520, so the 0xfd branch is reachable in
       production and was not reachable here. */
    unsigned char digest[32];
    unsigned char script[520];
    size_t sclen = size ? (size_t)(data[0] * 3) : 0;
    if (sclen > sizeof(script)) sclen = sizeof(script);
    for (size_t i = 0; i < sclen; i++) script[i] = data[i % (size ? size : 1)];
    pc_tx_sighash(hex, script, sclen, digest);

    free(hex);
    return 0;
}
