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

/* Everything Bob needs to know before he calls a payment money.
 *
 * A merchant who signs and stores a transaction without reading it is trusting
 * the payer to have built it honestly, which is the one thing a payment channel
 * is supposed to remove. So the transaction is parsed here: one input, the
 * funding outpoint, and an output to Bob for at least what was claimed. */

#include "channel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const unsigned char *p;
    size_t len, off;
    int    bad;
} rdr;

static void need(rdr *r, size_t n)
{
    if (r->off + n > r->len) r->bad = 1;
}

static uint64_t rd_u(rdr *r, size_t n)
{
    need(r, n);
    if (r->bad) return 0;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) v |= (uint64_t)r->p[r->off + i] << (8 * i);
    r->off += n;
    return v;
}

static uint64_t rd_varint(rdr *r)
{
    uint64_t first = rd_u(r, 1);
    if (r->bad) return 0;
    if (first < 0xfd) return first;
    if (first == 0xfd) return rd_u(r, 2);
    if (first == 0xfe) return rd_u(r, 4);
    return rd_u(r, 8);
}

/* Skip a length-prefixed script and optionally hand back where it started. */
static void rd_script(rdr *r, const unsigned char **out, size_t *outlen)
{
    uint64_t n = rd_varint(r);
    if (r->bad || n > r->len) { r->bad = 1; return; }
    need(r, (size_t)n);
    if (r->bad) return;
    if (out)    *out    = r->p + r->off;
    if (outlen) *outlen = (size_t)n;
    r->off += (size_t)n;
}

pc_result pc_tx_verify_payment(const pc_channel *ch,
                               const char *raw_tx_hex,
                               uint64_t claimed_to_bob_koinu)
{
    if (!ch || !raw_tx_hex) return PC_ERR_ARG;
    if (!ch->funding_txid[0]) return PC_ERR_STATE;

    /* the p2pkh script paying the key in the redeem script */
    dogecoin_pubkey bob;
    dogecoin_pubkey_init(&bob);
    bob.compressed = true;
    size_t pklen = 0;
    utils_hex_to_bin(ch->bob_pubkey_hex, bob.pubkey, 66, &pklen);
    if (pklen != 33) return PC_ERR_ARG;
    uint160_t bob_h160;
    dogecoin_pubkey_get_hash160(&bob, bob_h160);

    unsigned char want[25];
    want[0] = 0x76; want[1] = 0xa9; want[2] = 0x14;
    memcpy(want + 3, bob_h160, 20);
    want[23] = 0x88; want[24] = 0xac;

    size_t hl = strlen(raw_tx_hex);
    if (hl == 0 || (hl % 2)) return PC_ERR_ARG;
    unsigned char *buf = (unsigned char *)malloc(hl / 2 + 1);
    if (!buf) return PC_ERR_ARG;
    size_t blen = 0;
    utils_hex_to_bin(raw_tx_hex, buf, hl, &blen);
    if (blen != hl / 2) { free(buf); return PC_ERR_ARG; }

    rdr r = { buf, blen, 0, 0 };
    pc_result rc = PC_ERR_PSBT;

    rd_u(&r, 4);                                  /* version */

    uint64_t nin = rd_varint(&r);
    if (r.bad || nin != 1) goto out;              /* the channel spends one utxo */

    unsigned char prev[32];
    need(&r, 32);
    if (r.bad) goto out;
    memcpy(prev, r.p + r.off, 32);
    r.off += 32;
    uint32_t vout = (uint32_t)rd_u(&r, 4);
    rd_script(&r, NULL, NULL);                    /* scriptSig */
    rd_u(&r, 4);                                  /* sequence  */
    if (r.bad) goto out;

    /* txids are displayed reversed */
    unsigned char disp[32];
    for (int i = 0; i < 32; i++) disp[i] = prev[31 - i];
    char txid[65];
    utils_bin_to_hex(disp, 32, txid);
    if (strcmp(txid, ch->funding_txid) != 0)      goto out;
    if (vout != (uint32_t)ch->funding_vout)       goto out;

    uint64_t nout = rd_varint(&r);
    if (r.bad || nout == 0 || nout > 16) goto out;

    uint64_t to_bob = 0, total = 0;
    for (uint64_t i = 0; i < nout; i++) {
        uint64_t value = rd_u(&r, 8);
        const unsigned char *spk = NULL;
        size_t spklen = 0;
        rd_script(&r, &spk, &spklen);
        if (r.bad) goto out;
        total += value;

        if (spklen == sizeof(want) && memcmp(spk, want, sizeof(want)) == 0)
            to_bob += value;
    }
    rd_u(&r, 4);                                  /* locktime */
    if (r.bad) goto out;
    if (r.off != r.len) goto out;                 /* trailing bytes: not our tx */

    /* The fee is capacity minus what the outputs spend, so an input that does
       not cover the outputs would be a transaction no node will relay. */
    if (total > ch->capacity_koinu) { rc = PC_ERR_AMOUNT; goto out; }
    if (to_bob < claimed_to_bob_koinu) { rc = PC_ERR_AMOUNT; goto out; }

    rc = PC_OK;
out:
    free(buf);
    return rc;
}
