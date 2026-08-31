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

/* Builds a seed for fuzz_txcheck, and prints the constants the harness has to
 * carry for that seed to be worth anything.
 *
 * A seed that spends a different outpoint than the harness's channel dies at
 * the txid comparison, which is a 32 byte equality no mutation will reproduce.
 * Everything past it, the whole output loop and all of verify_sigs, then never
 * runs. The seed and the harness have to agree, so they are generated together
 * here rather than collected separately and hoped over.
 *
 * Run it, paste the constants into fuzz_txcheck.c, and write the last line to
 * fuzz/corpus/txcheck/closing-tx.hex. */

#include "channel.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *funding_tx(const char *p2sh, const char *change, char *txid_out)
{
    int tix = start_transaction();
    if (tix < 0) return NULL;
    if (!add_utxo(tix,
        (char *)"b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074", 0))
        return NULL;
    if (!add_output(tix, (char *)p2sh, (char *)"100.0")) return NULL;
    char *hex = (char *)malloc(DOGECOIN_MAX_TX_HEX_LEN);
    if (!hex) return NULL;
    if (!finalize_transaction_ex(tix, (char *)p2sh, (char *)"1.0",
                                 (char *)"150.0", (char *)change,
                                 hex, DOGECOIN_MAX_TX_HEX_LEN)) {
        free(hex); return NULL;
    }
    size_t hl = strlen(hex), blen = 0;
    unsigned char *b = (unsigned char *)malloc(hl / 2 + 1);
    utils_hex_to_bin(hex, b, hl, &blen);
    dogecoin_tx *tx = dogecoin_tx_new();
    dogecoin_tx_deserialize(b, blen, tx, NULL);
    free(b);
    uint256_t h;
    dogecoin_tx_hash(tx, h);
    unsigned char rev[32];
    for (int i = 0; i < 32; i++) rev[i] = h[31 - i];
    utils_bin_to_hex(rev, 32, txid_out);
    dogecoin_tx_free(tx);
    remove_all();
    return hex;
}

int main(void)
{
    dogecoin_ecc_start();
    int rc = 1;

    char awif[PRIVKEYWIFLEN], aaddr[P2PKHLEN];
    char bwif[PRIVKEYWIFLEN], baddr[P2PKHLEN];
    if (!generatePrivPubKeypair(awif, aaddr, false)) goto done;
    if (!generatePrivPubKeypair(bwif, baddr, false)) goto done;

    char apub[PUBKEYHEXLEN], bpub[PUBKEYHEXLEN];
    size_t n = sizeof(apub);
    if (!getPubkeyFromPrivkey(awif, false, apub, &n)) goto done;
    n = sizeof(bpub);
    if (!getPubkeyFromPrivkey(bwif, false, bpub, &n)) goto done;

    pc_channel ch;
    if (pc_channel_init(&ch, apub, bpub, 300000, PC_CHAIN_MAIN) != PC_OK) goto done;

    char ftxid[65] = {0};
    char *ftx = funding_tx(ch.p2sh_address, aaddr, ftxid);
    if (!ftx) goto done;

    int vout = 0;
    uint64_t capacity = 0;
    if (pc_tx_find_channel_output(&ch, ftx, ftxid, &vout, &capacity) != PC_OK) goto done;
    if (pc_channel_set_funding(&ch, ftxid, vout, capacity) != PC_OK) goto done;

    char *psbt = NULL;
    if (pc_payment_create(&ch, ftx, awif, aaddr, baddr,
                          2000000000ULL, 100000000ULL, &psbt) != PC_OK) goto done;

    char *raw = NULL;
    if (pc_payment_countersign(&ch, psbt, bwif, &raw) != PC_OK) goto done;

    /* it has to be a transaction the reader accepts, or the seed starts from a
       rejection and the fuzzer works uphill from there */
    if (pc_tx_verify_payment(&ch, raw, 2000000000ULL) != PC_OK) {
        fprintf(stderr, "mkseed: the transaction it built does not verify\n");
        goto done;
    }

    printf("/* paste into fuzz_txcheck.c */\n");
    printf("static const char *ALICE_PUB =\n    \"%s\";\n", apub);
    printf("static const char *BOB_PUB =\n    \"%s\";\n", bpub);
    printf("    \"%s\",\n", ftxid);
    printf("    vout %d, capacity %" PRIu64 "\n", vout, capacity);
    printf("/* write this to fuzz/corpus/txcheck/closing-tx.hex */\n");
    printf("%s\n", raw);

    dogecoin_free(psbt);
    dogecoin_free(raw);
    free(ftx);
    rc = 0;
done:
    dogecoin_ecc_stop();
    return rc;
}
