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

#include "channel.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *pc_strerror(pc_result r)
{
    switch (r) {
    case PC_OK:          return "ok";
    case PC_ERR_ARG:     return "bad argument";
    case PC_ERR_KEY:     return "key would not decode";
    case PC_ERR_SCRIPT:  return "redeem script would not build";
    case PC_ERR_PSBT:    return "psbt would not parse, sign or finalize";
    case PC_ERR_STATE:   return "channel not in a state that allows this";
    case PC_ERR_AMOUNT:  return "payment does not respect the channel balance";
    }
    return "unknown";
}

/* ── helpers ─────────────────────────────────────────────────── */

static int hexcat(char *dst, size_t cap, size_t *len, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(dst + *len, cap - *len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap - *len) return 0;
    *len += (size_t)n;
    return 1;
}

/* koinu to the decimal DOGE string the transaction overlay expects */
void pc_koinu_to_doge(uint64_t koinu, char *out, size_t cap)
{
    snprintf(out, cap, "%" PRIu64 ".%08" PRIu64,
             (uint64_t)(koinu / 100000000ULL), (uint64_t)(koinu % 100000000ULL));
}

/* The inverse, without floating point: a double cannot hold koinu exactly past
   about 90 million DOGE, and rounding an amount is not an option. */
pc_result pc_doge_to_koinu(const char *doge, uint64_t *koinu_out)
{
    if (!doge || !koinu_out) return PC_ERR_ARG;
    uint64_t whole = 0, frac = 0;
    int digits = 0, seen = 0;
    const char *p = doge;

    for (; *p && *p != '.'; p++) {
        if (*p < '0' || *p > '9') return PC_ERR_ARG;
        if (whole > (UINT64_MAX - (uint64_t)(*p - '0')) / 10) return PC_ERR_ARG;
        whole = whole * 10 + (uint64_t)(*p - '0');
        seen = 1;
    }
    if (*p == '.') {
        for (p++; *p; p++) {
            if (*p < '0' || *p > '9') return PC_ERR_ARG;
            if (digits == 8) return PC_ERR_ARG;      /* finer than koinu */
            frac = frac * 10 + (uint64_t)(*p - '0');
            digits++;
            seen = 1;
        }
    }
    if (!seen) return PC_ERR_ARG;
    while (digits++ < 8) frac *= 10;
    if (whole > UINT64_MAX / 100000000ULL) return PC_ERR_ARG;
    uint64_t v = whole * 100000000ULL;
    if (v > UINT64_MAX - frac) return PC_ERR_ARG;
    *koinu_out = v + frac;
    return PC_OK;
}

static int hex_to_bytes(const char *hex, unsigned char **out, size_t *outlen)
{
    size_t hl = strlen(hex);
    if (hl == 0 || (hl % 2)) return 0;
    unsigned char *b = (unsigned char *)malloc(hl / 2 + 1);
    if (!b) return 0;
    size_t n = 0;
    utils_hex_to_bin(hex, b, hl, &n);
    if (n != hl / 2) { free(b); return 0; }
    *out = b; *outlen = n;
    return 1;
}

/* ── channel setup ───────────────────────────────────────────── */

pc_result pc_channel_init(pc_channel *ch,
                          const char *alice_pubkey_hex,
                          const char *bob_pubkey_hex,
                          uint32_t locktime,
                          int is_testnet)
{
    if (!ch || !alice_pubkey_hex || !bob_pubkey_hex) return PC_ERR_ARG;
    if (strlen(alice_pubkey_hex) != 66 || strlen(bob_pubkey_hex) != 66)
        return PC_ERR_ARG;   /* compressed pubkeys only */
    if (locktime == 0) return PC_ERR_ARG;

    memset(ch, 0, sizeof(*ch));
    snprintf(ch->alice_pubkey_hex, sizeof(ch->alice_pubkey_hex), "%s", alice_pubkey_hex);
    snprintf(ch->bob_pubkey_hex,   sizeof(ch->bob_pubkey_hex),   "%s", bob_pubkey_hex);
    ch->locktime   = locktime;
    ch->is_testnet = is_testnet ? 1 : 0;

    /* The locktime is pushed as a minimally encoded little-endian number.
       Heights below 500000000 are block heights per BIP65; three bytes cover
       every height this chain will see for a long time, and a fourth would be
       read as a negative number without a trailing zero byte. */
    if (locktime >= 500000000u) return PC_ERR_ARG;   /* timestamps not supported */
    unsigned char lt[4];
    size_t ltlen = 0;
    uint32_t v = locktime;
    while (v) { lt[ltlen++] = (unsigned char)(v & 0xFF); v >>= 8; }
    if (ltlen == 0) return PC_ERR_ARG;
    if (lt[ltlen - 1] & 0x80) lt[ltlen++] = 0x00;    /* keep it positive */

    size_t p = 0;
    char *s = ch->redeem_script_hex;
    size_t cap = sizeof(ch->redeem_script_hex);

    if (!hexcat(s, cap, &p, "63")) return PC_ERR_SCRIPT;            /* OP_IF   */
    if (!hexcat(s, cap, &p, "%02x", (unsigned)ltlen)) return PC_ERR_SCRIPT;
    for (size_t i = 0; i < ltlen; i++)
        if (!hexcat(s, cap, &p, "%02x", lt[i])) return PC_ERR_SCRIPT;
    if (!hexcat(s, cap, &p, "b1")) return PC_ERR_SCRIPT;            /* CLTV    */
    if (!hexcat(s, cap, &p, "75")) return PC_ERR_SCRIPT;            /* OP_DROP */
    if (!hexcat(s, cap, &p, "21%s", ch->alice_pubkey_hex)) return PC_ERR_SCRIPT;
    if (!hexcat(s, cap, &p, "ad")) return PC_ERR_SCRIPT;            /* CHECKSIGVERIFY */
    if (!hexcat(s, cap, &p, "67")) return PC_ERR_SCRIPT;            /* OP_ELSE */
    if (!hexcat(s, cap, &p, "52")) return PC_ERR_SCRIPT;            /* OP_2    */
    if (!hexcat(s, cap, &p, "68")) return PC_ERR_SCRIPT;            /* OP_ENDIF*/
    if (!hexcat(s, cap, &p, "21%s", ch->alice_pubkey_hex)) return PC_ERR_SCRIPT;
    if (!hexcat(s, cap, &p, "21%s", ch->bob_pubkey_hex))   return PC_ERR_SCRIPT;
    if (!hexcat(s, cap, &p, "52ae")) return PC_ERR_SCRIPT;          /* OP_2 CHECKMULTISIG */

    if (!get_p2sh_address_from_script(ch->redeem_script_hex, ch->is_testnet,
                                      ch->p2sh_address, sizeof(ch->p2sh_address)))
        return PC_ERR_SCRIPT;

    return PC_OK;
}

pc_result pc_channel_set_funding(pc_channel *ch, const char *txid_hex,
                                 int vout, uint64_t capacity_koinu)
{
    if (!ch || !txid_hex || vout < 0 || capacity_koinu == 0) return PC_ERR_ARG;
    if (strlen(txid_hex) != 64) return PC_ERR_ARG;
    if (!ch->p2sh_address[0]) return PC_ERR_STATE;

    snprintf(ch->funding_txid, sizeof(ch->funding_txid), "%s", txid_hex);
    ch->funding_vout      = vout;
    ch->capacity_koinu    = capacity_koinu;
    ch->paid_to_bob_koinu = 0;
    return PC_OK;
}

/* ── Alice ───────────────────────────────────────────────────── */

pc_result pc_payment_create(const pc_channel *ch,
                            const char *funding_tx_hex,
                            const char *alice_wif,
                            const char *alice_addr,
                            const char *bob_addr,
                            uint64_t to_bob_koinu,
                            uint64_t fee_koinu,
                            char **psbt_hex_out)
{
    if (!ch || !funding_tx_hex || !alice_wif || !alice_addr || !bob_addr ||
        !psbt_hex_out) return PC_ERR_ARG;
    if (!ch->funding_txid[0]) return PC_ERR_STATE;
    if (to_bob_koinu == 0 || to_bob_koinu + fee_koinu > ch->capacity_koinu)
        return PC_ERR_AMOUNT;

    *psbt_hex_out = NULL;
    pc_result rc = PC_ERR_PSBT;

    dogecoin_tx    *funding = NULL, *spend = NULL;
    dogecoin_psbt  *psbt    = NULL;
    unsigned char  *fbytes  = NULL, *rbytes = NULL;
    char           *unsigned_hex = NULL;
    unsigned char  *ubytes  = NULL;

    /* the spending transaction, built through the overlay so we never touch
       tx.h: one input, Bob's payment, the remainder back to Alice */
    int tix = start_transaction();
    if (tix < 0) return PC_ERR_PSBT;

    char amt[32], fee[32], total[32];
    pc_koinu_to_doge(to_bob_koinu, amt, sizeof(amt));
    pc_koinu_to_doge(fee_koinu, fee, sizeof(fee));
    pc_koinu_to_doge(ch->capacity_koinu, total, sizeof(total));

    if (!add_utxo(tix, (char *)ch->funding_txid, ch->funding_vout)) goto out;
    if (!add_output(tix, (char *)bob_addr, amt))                    goto out;

    /* finalize_transaction() hands back utils_uint8_to_hex()'s static buffer,
       not heap memory: it must not be freed, and the next call overwrites it.
       Copy before doing anything else that might serialize. */
    {
        const char *tmp = finalize_transaction(tix, (char *)bob_addr, fee, total,
                                               (char *)alice_addr);
        if (!tmp) goto out;
        unsigned_hex = strdup(tmp);
        if (!unsigned_hex) goto out;
    }

    size_t ulen = 0;
    if (!hex_to_bytes(unsigned_hex, &ubytes, &ulen)) goto out;
    spend = dogecoin_tx_new();
    if (dogecoin_tx_deserialize(ubytes, ulen, spend, NULL) == 0) goto out;

    psbt = dogecoin_psbt_create(spend);
    if (!psbt) goto out;

    /* updater: the funding transaction and the redeem script it pays to */
    size_t flen = 0;
    if (!hex_to_bytes(funding_tx_hex, &fbytes, &flen)) goto out;
    funding = dogecoin_tx_new();
    if (dogecoin_tx_deserialize(fbytes, flen, funding, NULL) == 0) goto out;
    if (!dogecoin_psbt_input_set_utxo(psbt, 0, funding)) goto out;

    size_t rlen = 0;
    if (!hex_to_bytes(ch->redeem_script_hex, &rbytes, &rlen)) goto out;
    if (!dogecoin_psbt_input_set_redeemscript(psbt, 0, rbytes, rlen)) goto out;

    /* signer: Alice only. Bob countersigns when he accepts. */
    dogecoin_key key;
    dogecoin_privkey_init(&key);
    const dogecoin_chainparams *chain = ch->is_testnet
        ? &dogecoin_chainparams_test : &dogecoin_chainparams_main;
    if (!dogecoin_privkey_decode_wif((char *)alice_wif, chain, &key)) {
        rc = PC_ERR_KEY; goto out;
    }
    if (!dogecoin_psbt_sign_input(psbt, 0, &key)) {
        dogecoin_privkey_cleanse(&key);
        goto out;
    }
    dogecoin_privkey_cleanse(&key);

    *psbt_hex_out = dogecoin_psbt_to_hex(psbt);
    rc = *psbt_hex_out ? PC_OK : PC_ERR_PSBT;

out:
    free(unsigned_hex);
    free(ubytes); free(fbytes); free(rbytes);
    if (psbt)    dogecoin_psbt_free(psbt);
    if (spend)   dogecoin_tx_free(spend);
    if (funding) dogecoin_tx_free(funding);
    remove_all();
    return rc;
}

/* ── Bob ─────────────────────────────────────────────────────── */

pc_result pc_payment_accept(pc_channel *ch, const char *psbt_hex,
                            uint64_t claimed_to_bob_koinu)
{
    if (!ch || !psbt_hex) return PC_ERR_ARG;
    if (!ch->funding_txid[0]) return PC_ERR_STATE;

    /* A unidirectional channel only ever moves value toward Bob. A payment
       that does not beat the last one is either a replay or an attempt to
       walk the balance back, and either way Bob keeps the one he has. */
    if (claimed_to_bob_koinu <= ch->paid_to_bob_koinu) return PC_ERR_AMOUNT;
    if (claimed_to_bob_koinu > ch->capacity_koinu)     return PC_ERR_AMOUNT;

    dogecoin_psbt *psbt = NULL;
    if (!dogecoin_psbt_from_hex(psbt_hex, &psbt) || !psbt) return PC_ERR_PSBT;

    pc_result rc = PC_ERR_PSBT;
    if (dogecoin_psbt_num_inputs(psbt) != 1) goto out;

    /* it must carry Alice's signature already */
    if (dogecoin_psbt_input_num_partial_sigs(psbt, 0) < 1) goto out;

    /* and it must be spending this channel's redeem script */
    size_t rlen = 0;
    if (!dogecoin_psbt_input_get_redeemscript(psbt, 0, NULL, 0, &rlen)) {
        if (rlen == 0) goto out;
    }
    unsigned char rbuf[520];
    if (rlen > sizeof(rbuf)) goto out;
    if (!dogecoin_psbt_input_get_redeemscript(psbt, 0, rbuf, sizeof(rbuf), &rlen)) goto out;
    char rhex[PC_MAX_SCRIPT_HEX];
    if (rlen * 2 + 1 > sizeof(rhex)) goto out;
    utils_bin_to_hex(rbuf, rlen, rhex);
    if (strcmp(rhex, ch->redeem_script_hex) != 0) goto out;

    ch->paid_to_bob_koinu = claimed_to_bob_koinu;
    rc = PC_OK;
out:
    if (psbt) dogecoin_psbt_free(psbt);
    return rc;
}

pc_result pc_payment_countersign(const pc_channel *ch, const char *psbt_hex,
                                 const char *bob_wif, char **raw_tx_hex_out)
{
    if (!ch || !psbt_hex || !bob_wif || !raw_tx_hex_out) return PC_ERR_ARG;
    *raw_tx_hex_out = NULL;

    dogecoin_psbt *psbt = NULL;
    unsigned char *rbytes = NULL;
    pc_result rc = PC_ERR_PSBT;

    if (!dogecoin_psbt_from_hex(psbt_hex, &psbt) || !psbt) return PC_ERR_PSBT;
    if (dogecoin_psbt_num_inputs(psbt) != 1) goto out;

    dogecoin_key key;
    dogecoin_privkey_init(&key);
    const dogecoin_chainparams *chain = ch->is_testnet
        ? &dogecoin_chainparams_test : &dogecoin_chainparams_main;
    if (!dogecoin_privkey_decode_wif((char *)bob_wif, chain, &key)) {
        rc = PC_ERR_KEY; goto out;
    }
    if (!dogecoin_psbt_sign_input(psbt, 0, &key)) {
        dogecoin_privkey_cleanse(&key); goto out;
    }
    dogecoin_privkey_cleanse(&key);

    /* Two signatures now, Alice's and Bob's. No built-in finalizer can build
       the scriptSig for this redeem script because OP_IF does not classify, so
       assemble it here:
           OP_0 <sig A> <sig B> OP_0 <redeem script>
       The leading OP_0 is CHECKMULTISIG's off-by-one pop. The trailing OP_0 is
       the branch selector: false takes OP_ELSE, the cooperative 2-of-2. */
    if (dogecoin_psbt_input_num_partial_sigs(psbt, 0) != 2) goto out;

    /* CHECKMULTISIG requires the signatures in the order the pubkeys appear in
       the redeem script, which is Alice then Bob. */
    unsigned char sigs[2][128];
    size_t siglen[2] = { 0, 0 };
    unsigned char pk[2][64];
    size_t pklen[2] = { 0, 0 };
    for (size_t i = 0; i < 2; i++) {
        if (!dogecoin_psbt_input_get_partial_sig(psbt, 0, i,
                                                 pk[i], sizeof(pk[i]), &pklen[i],
                                                 sigs[i], sizeof(sigs[i]), &siglen[i]))
            goto out;
    }
    char pkhex[2][PUBKEYHEXLEN];
    for (size_t i = 0; i < 2; i++) utils_bin_to_hex(pk[i], pklen[i], pkhex[i]);
    int alice_idx = (strcmp(pkhex[0], ch->alice_pubkey_hex) == 0) ? 0 : 1;
    int bob_idx   = alice_idx ^ 1;
    if (strcmp(pkhex[alice_idx], ch->alice_pubkey_hex) != 0 ||
        strcmp(pkhex[bob_idx],   ch->bob_pubkey_hex)   != 0)
        goto out;

    size_t rlen = 0;
    if (!hex_to_bytes(ch->redeem_script_hex, &rbytes, &rlen)) goto out;

    unsigned char ss[1024];
    size_t n = 0;
    ss[n++] = 0x00;                                  /* OP_0, the extra pop   */
    ss[n++] = (unsigned char)siglen[alice_idx];
    memcpy(ss + n, sigs[alice_idx], siglen[alice_idx]); n += siglen[alice_idx];
    ss[n++] = (unsigned char)siglen[bob_idx];
    memcpy(ss + n, sigs[bob_idx], siglen[bob_idx]);   n += siglen[bob_idx];
    ss[n++] = 0x00;                                  /* branch selector: ELSE */
    if (rlen < 76) {
        ss[n++] = (unsigned char)rlen;
    } else {
        ss[n++] = 0x4c;                              /* OP_PUSHDATA1          */
        ss[n++] = (unsigned char)rlen;
    }
    if (n + rlen > sizeof(ss)) goto out;
    memcpy(ss + n, rbytes, rlen); n += rlen;

    if (!dogecoin_psbt_input_set_final_scriptsig(psbt, 0, ss, n)) goto out;

    *raw_tx_hex_out = dogecoin_psbt_extract_hex(psbt);
    rc = *raw_tx_hex_out ? PC_OK : PC_ERR_PSBT;
out:
    free(rbytes);
    if (psbt) dogecoin_psbt_free(psbt);
    return rc;
}
