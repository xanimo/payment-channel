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

/* An Alice who signs honestly and builds dishonestly.
 *
 * Every payment here carries two real signatures over the transaction it
 * actually is, so verify_sigs() passes on all of them. What varies is the parts
 * of the transaction Alice controls and Bob has to decide about: the version,
 * the output values, the scripts on outputs that are not his, the locktime and
 * the sequence.
 *
 * The property under test is narrow and is the one that matters to a merchant:
 * if Bob acks, the transaction he is holding has to be one a default node would
 * accept and mine. Anything he acks that no node will take is goods shipped for
 * nothing, and it is not a crash, so no fuzzer reports it. */

#include "channel.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { uint64_t value; unsigned char spk[64]; size_t spklen; } out_t;

static size_t put_le(unsigned char *o, uint64_t v, size_t n)
{
    for (size_t i = 0; i < n; i++) o[i] = (unsigned char)((v >> (8 * i)) & 0xff);
    return n;
}

static size_t ser(const pc_channel *ch, uint32_t version, uint32_t sequence,
                  uint32_t locktime, const out_t *outs, size_t nout,
                  const unsigned char *ss, size_t sslen, unsigned char *o)
{
    size_t n = 0;
    n += put_le(o + n, version, 4);
    o[n++] = 0x01;
    unsigned char txid[32];
    size_t tn = 0;
    utils_hex_to_bin(ch->funding_txid, txid, 64, &tn);
    for (int i = 0; i < 32; i++) o[n + i] = txid[31 - i];
    n += 32;
    n += put_le(o + n, (uint64_t)ch->funding_vout, 4);
    if (ss) {
        if (sslen < 0xfd) o[n++] = (unsigned char)sslen;
        else { o[n++] = 0xfd; n += put_le(o + n, sslen, 2); }
        memcpy(o + n, ss, sslen); n += sslen;
    } else o[n++] = 0x00;
    n += put_le(o + n, sequence, 4);
    o[n++] = (unsigned char)nout;
    for (size_t k = 0; k < nout; k++) {
        n += put_le(o + n, outs[k].value, 8);
        o[n++] = (unsigned char)outs[k].spklen;
        memcpy(o + n, outs[k].spk, outs[k].spklen);
        n += outs[k].spklen;
    }
    n += put_le(o + n, locktime, 4);
    return n;
}

/* signs whatever it is given, which is the point */
static char *forge(const pc_channel *ch, const char *awif, const char *bwif,
                   uint32_t version, uint32_t sequence, uint32_t locktime,
                   const out_t *outs, size_t nout)
{
    unsigned char redeem[520];
    size_t rlen = 0;
    utils_hex_to_bin(ch->redeem_script_hex, redeem,
                     strlen(ch->redeem_script_hex), &rlen);

    unsigned char buf[4096];
    size_t un = ser(ch, version, sequence, locktime, outs, nout, NULL, 0, buf);
    char *uhex = (char *)malloc(un * 2 + 1);
    if (!uhex) return NULL;
    utils_bin_to_hex(buf, un, uhex);

    unsigned char hash[32];
    pc_result r = pc_tx_sighash(uhex, redeem, rlen, hash);
    free(uhex);
    if (r != PC_OK) return NULL;

    unsigned char sig[2][80];
    size_t sl[2] = { sizeof(sig[0]), sizeof(sig[1]) };
    const char *wifs[2] = { awif, bwif };
    for (int k = 0; k < 2; k++) {
        dogecoin_key key;
        dogecoin_privkey_init(&key);
        if (!dogecoin_privkey_decode_wif((char *)wifs[k],
                                         pc_chainparams(ch->chain), &key)) return NULL;
        int ok = dogecoin_ecc_sign(key.privkey, hash, sig[k], &sl[k]);
        dogecoin_privkey_cleanse(&key);
        if (!ok) return NULL;
        sig[k][sl[k]++] = 0x01;
    }

    unsigned char ss[1024];
    size_t sn = 0;
    ss[sn++] = 0x00;
    for (int k = 0; k < 2; k++) {
        ss[sn++] = (unsigned char)sl[k];
        memcpy(ss + sn, sig[k], sl[k]); sn += sl[k];
    }
    ss[sn++] = 0x00;
    if (rlen < 76) ss[sn++] = (unsigned char)rlen;
    else { ss[sn++] = 0x4c; ss[sn++] = (unsigned char)rlen; }
    memcpy(ss + sn, redeem, rlen); sn += rlen;

    size_t fn = ser(ch, version, sequence, locktime, outs, nout, ss, sn, buf);
    char *hex = (char *)malloc(fn * 2 + 1);
    if (!hex) return NULL;
    utils_bin_to_hex(buf, fn, hex);
    return hex;
}

static int failures = 0, checks = 0;

static void expect_refused(const pc_channel *ch, const char *raw,
                           uint64_t claimed, const char *what)
{
    checks++;
    if (!raw) { printf("  BUILD FAILED  %s\n", what); failures++; return; }
    pc_result r = pc_tx_verify_payment(ch, raw, claimed);
    if (r == PC_OK) {
        printf("  ACCEPTED      %s\n", what);
        failures++;
    } else {
        printf("  refused (%-38s) %s\n", pc_strerror(r), what);
    }
}

static void expect_accepted(const pc_channel *ch, const char *raw,
                            uint64_t claimed, const char *what)
{
    checks++;
    if (!raw) { printf("  BUILD FAILED  %s\n", what); failures++; return; }
    pc_result r = pc_tx_verify_payment(ch, raw, claimed);
    if (r != PC_OK) {
        printf("  WRONGLY REFUSED (%s) %s\n", pc_strerror(r), what);
        failures++;
    } else {
        printf("  accepted      %s\n", what);
    }
}

static void p2pkh(out_t *o, const unsigned char h160[20], uint64_t v)
{
    o->value = v;
    o->spk[0] = 0x76; o->spk[1] = 0xa9; o->spk[2] = 0x14;
    memcpy(o->spk + 3, h160, 20);
    o->spk[23] = 0x88; o->spk[24] = 0xac;
    o->spklen = 25;
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
    getPubkeyFromPrivkey(awif, false, apub, &n);
    n = sizeof(bpub);
    getPubkeyFromPrivkey(bwif, false, bpub, &n);

    pc_channel ch;
    if (pc_channel_init(&ch, apub, bpub, 300000, PC_CHAIN_MAIN) != PC_OK) goto done;
    if (pc_channel_set_funding(&ch,
            "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074",
            0, 10000000000ULL) != PC_OK) goto done;

    unsigned char ah[64], bh[64];
    dogecoin_base58_decode_check(aaddr, ah, sizeof(ah));
    dogecoin_base58_decode_check(baddr, bh, sizeof(bh));

    const uint64_t TO_BOB = 2000000000ULL;
    const uint64_t FEE    = 100000000ULL;
    const uint64_t CHANGE = 10000000000ULL - TO_BOB - FEE;

    out_t o[2];
    p2pkh(&o[0], bh + 1, TO_BOB);
    p2pkh(&o[1], ah + 1, CHANGE);

    printf("attacking a channel of %" PRIu64 " koinu, paying bob %" PRIu64 "\n\n",
           ch.capacity_koinu, TO_BOB);

    char *raw = forge(&ch, awif, bwif, 1, 0xffffffffu, 0, o, 2);
    expect_accepted(&ch, raw, TO_BOB, "the honest payment, as a control");
    free(raw);

    /* IsStandardTx: nVersion must be 1 or 2 */
    for (uint32_t v = 0; v < 4; v++) {
        if (v == 1 || v == 2) continue;
        char label[80];
        snprintf(label, sizeof(label), "nVersion %u, outside the standard range", v);
        raw = forge(&ch, awif, bwif, v, 0xffffffffu, 0, o, 2);
        expect_refused(&ch, raw, TO_BOB, label);
        free(raw);
    }
    raw = forge(&ch, awif, bwif, 0x7fffffffu, 0xffffffffu, 0, o, 2);
    expect_refused(&ch, raw, TO_BOB, "nVersion 0x7fffffff");
    free(raw);
    raw = forge(&ch, awif, bwif, 2, 0xffffffffu, 0, o, 2);
    expect_accepted(&ch, raw, TO_BOB, "nVersion 2 is standard and allowed");
    free(raw);

    /* IsStandardTx: every scriptPubKey must be a standard type. Bob checks the
       one paying him and has nothing to say about the others. */
    {
        out_t bad[2];
        bad[0] = o[0];
        bad[1].value = CHANGE;
        /* bare multisig: OP_1 <pubkey> OP_1 OP_CHECKMULTISIG */
        bad[1].spk[0] = 0x51; bad[1].spk[1] = 0x21;
        size_t pn = 0;
        utils_hex_to_bin(apub, bad[1].spk + 2, 66, &pn);
        bad[1].spk[35] = 0x51; bad[1].spk[36] = 0xae;
        bad[1].spklen = 37;
        raw = forge(&ch, awif, bwif, 1, 0xffffffffu, 0, bad, 2);
        expect_refused(&ch, raw, TO_BOB, "change output is a bare multisig");
        free(raw);

        /* a script that is not any standard type at all */
        bad[1].spk[0] = 0x51;            /* OP_TRUE */
        bad[1].spklen = 1;
        raw = forge(&ch, awif, bwif, 1, 0xffffffffu, 0, bad, 2);
        expect_refused(&ch, raw, TO_BOB, "change output is anyone-can-spend");
        free(raw);

        /* two OP_RETURN outputs: multi-op-return */
        out_t two[3];
        two[0] = o[0];
        two[1].value = 0; two[1].spk[0] = 0x6a; two[1].spklen = 1;
        two[2].value = CHANGE; memcpy(&two[2], &o[1], sizeof(out_t));
        two[1].value = 0; two[1].spk[0] = 0x6a; two[1].spklen = 1;
        raw = forge(&ch, awif, bwif, 1, 0xffffffffu, 0, two, 3);
        expect_refused(&ch, raw, TO_BOB, "an unspendable zero-value output");
        free(raw);
    }

    /* the ones already closed, kept so they stay closed */
    raw = forge(&ch, awif, bwif, 1, 0xfffffffeu, 0, o, 2);
    expect_refused(&ch, raw, TO_BOB, "non-final sequence");
    free(raw);
    raw = forge(&ch, awif, bwif, 1, 0xffffffffu, 900000, o, 2);
    expect_refused(&ch, raw, TO_BOB, "a locktime in the future");
    free(raw);
    {
        out_t ovf[2];
        ovf[0] = o[0]; ovf[0].value = 0xFFFFFFFFFFFFFFFFULL;
        ovf[1] = o[1]; ovf[1].value = ch.capacity_koinu + 1 - pc_min_fee(400, 0);
        raw = forge(&ch, awif, bwif, 1, 0xffffffffu, 0, ovf, 2);
        expect_refused(&ch, raw, TO_BOB, "output values that wrap the total");
        free(raw);
    }
    {
        out_t dust[2];
        dust[0] = o[0];
        dust[1] = o[1]; dust[1].value = 1000;
        raw = forge(&ch, awif, bwif, 1, 0xffffffffu, 0, dust, 2);
        expect_refused(&ch, raw, TO_BOB, "a change output below the dust limit");
        free(raw);
    }

    /* The per-output bound is relative to the capacity, and the capacity comes
       from the funding transaction Alice supplied. If she can set it above what
       money exists, the bound stops bounding and the wrap comes back. */
    {
        pc_channel wide;
        if (pc_channel_init(&wide, apub, bpub, 300000, PC_CHAIN_MAIN) == PC_OK) {
            checks++;
            if (pc_channel_set_funding(&wide,
                    "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074",
                    0, 0xFFFFFFFFFFFFFFFFULL) == PC_OK) {
                printf("  ACCEPTED      a capacity above every coin that exists\n");
                failures++;
                out_t big[2];
                p2pkh(&big[0], bh + 1, 0xFFFFFFFFFFFFFF00ULL);
                p2pkh(&big[1], ah + 1, 0x100ULL);
                raw = forge(&wide, awif, bwif, 1, 0xffffffffu, 0, big, 2);
                expect_refused(&wide, raw, TO_BOB,
                               "output values that wrap, with capacity unbounded");
                free(raw);
            } else {
                printf("  refused (capacity above MAX_MONEY              ) "
                       "a capacity above every coin that exists\n");
            }
        }
    }

    printf("\n%d attacks, %d got through\n", checks, failures);
    rc = failures ? 1 : 0;
done:
    dogecoin_ecc_stop();
    return rc;
}
