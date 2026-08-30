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

const dogecoin_chainparams *pc_chainparams(pc_chain chain)
{
    switch (chain) {
    case PC_CHAIN_TEST:    return &dogecoin_chainparams_test;
    case PC_CHAIN_REGTEST: return &dogecoin_chainparams_regtest;
    case PC_CHAIN_MAIN:    break;
    }
    return &dogecoin_chainparams_main;
}

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
                          pc_chain chain)
{
    if (!ch || !alice_pubkey_hex || !bob_pubkey_hex) return PC_ERR_ARG;
    if (strlen(alice_pubkey_hex) != 66 || strlen(bob_pubkey_hex) != 66)
        return PC_ERR_ARG;   /* compressed pubkeys only */
    if (locktime == 0) return PC_ERR_ARG;

    memset(ch, 0, sizeof(*ch));
    snprintf(ch->alice_pubkey_hex, sizeof(ch->alice_pubkey_hex), "%s", alice_pubkey_hex);
    snprintf(ch->bob_pubkey_hex,   sizeof(ch->bob_pubkey_hex),   "%s", bob_pubkey_hex);
    ch->locktime = locktime;
    ch->chain    = chain;

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
    if (!hexcat(s, cap, &p, "ac")) return PC_ERR_SCRIPT;            /* CHECKSIG */
    if (!hexcat(s, cap, &p, "67")) return PC_ERR_SCRIPT;            /* OP_ELSE */
    if (!hexcat(s, cap, &p, "52")) return PC_ERR_SCRIPT;            /* OP_2    */
    if (!hexcat(s, cap, &p, "21%s", ch->alice_pubkey_hex)) return PC_ERR_SCRIPT;
    if (!hexcat(s, cap, &p, "21%s", ch->bob_pubkey_hex))   return PC_ERR_SCRIPT;
    if (!hexcat(s, cap, &p, "52ae")) return PC_ERR_SCRIPT;          /* OP_2 CHECKMULTISIG */
    if (!hexcat(s, cap, &p, "68")) return PC_ERR_SCRIPT;            /* OP_ENDIF*/

    /* the helper takes a boolean, and regtest shares testnet's 0xc4 script
       prefix, so either non-main chain wants the same argument here */
    if (!get_p2sh_address_from_script(ch->redeem_script_hex,
                                      ch->chain != PC_CHAIN_MAIN,
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

/* ── Opening ─────────────────────────────────────────────────── */

pc_result pc_redeem_parse(const char *redeem_hex, char alice_pubkey_hex[PUBKEYHEXLEN],
                          char bob_pubkey_hex[PUBKEYHEXLEN], uint32_t *locktime_out)
{
    if (!redeem_hex || !alice_pubkey_hex || !bob_pubkey_hex) return PC_ERR_ARG;

    unsigned char *b = NULL;
    size_t n = 0;
    if (!hex_to_bytes(redeem_hex, &b, &n)) return PC_ERR_ARG;

    pc_result rc = PC_ERR_SCRIPT;
    size_t i = 0;
    #define TAKE(x) do { if (i >= n || b[i] != (x)) goto out; i++; } while (0)

    TAKE(0x63);                                       /* OP_IF */
    if (i >= n) goto out;
    size_t ltlen = b[i++];
    if (ltlen < 1 || ltlen > 4 || i + ltlen > n) goto out;
    uint32_t locktime = 0;
    for (size_t k = 0; k < ltlen; k++) locktime |= (uint32_t)b[i + k] << (8 * k);
    i += ltlen;
    TAKE(0xb1);                                       /* CHECKLOCKTIMEVERIFY */
    TAKE(0x75);                                       /* OP_DROP */
    TAKE(0x21);
    if (i + 33 > n) goto out;
    size_t alice_at = i; i += 33;
    TAKE(0xac);                                       /* CHECKSIG */
    TAKE(0x67);                                       /* OP_ELSE */
    TAKE(0x52);                                       /* OP_2 */
    TAKE(0x21);
    if (i + 33 > n) goto out;
    size_t alice2_at = i; i += 33;
    TAKE(0x21);
    if (i + 33 > n) goto out;
    size_t bob_at = i; i += 33;
    TAKE(0x52);                                       /* OP_2 */
    TAKE(0xae);                                       /* CHECKMULTISIG */
    TAKE(0x68);                                       /* OP_ENDIF */
    if (i != n) goto out;                             /* trailing bytes */
    #undef TAKE

    /* the refund branch and the multisig must name the same Alice */
    if (memcmp(b + alice_at, b + alice2_at, 33) != 0) goto out;
    if (locktime == 0 || locktime >= 500000000u) goto out;

    utils_bin_to_hex(b + alice_at, 33, alice_pubkey_hex);
    utils_bin_to_hex(b + bob_at,   33, bob_pubkey_hex);
    if (locktime_out) *locktime_out = locktime;
    rc = PC_OK;
out:
    free(b);
    return rc;
}

/* A transaction with one input and no outputs, serialized by hand. The overlay
   will not build one: finalize_transaction() needs somewhere to send the money,
   and the whole point of the opening PSBT is that it does not say yet. */
static int unsigned_1in_0out(const char *txid_display, uint32_t vout,
                             char *out, size_t cap)
{
    unsigned char prev[32];
    size_t n = 0;
    utils_hex_to_bin((char *)txid_display, prev, 64, &n);
    if (n != 32) return 0;

    unsigned char tx[64];
    size_t i = 0;
    tx[i++] = 0x01; tx[i++] = 0x00; tx[i++] = 0x00; tx[i++] = 0x00;  /* version */
    tx[i++] = 0x01;                                                  /* 1 input */
    for (int k = 31; k >= 0; k--) tx[i++] = prev[k];                 /* internal order */
    tx[i++] = (unsigned char)(vout & 0xFF);
    tx[i++] = (unsigned char)((vout >> 8) & 0xFF);
    tx[i++] = (unsigned char)((vout >> 16) & 0xFF);
    tx[i++] = (unsigned char)((vout >> 24) & 0xFF);
    tx[i++] = 0x00;                                                  /* empty scriptSig */
    tx[i++] = 0xFF; tx[i++] = 0xFF; tx[i++] = 0xFF; tx[i++] = 0xFF;  /* sequence */
    tx[i++] = 0x00;                                                  /* 0 outputs */
    tx[i++] = 0x00; tx[i++] = 0x00; tx[i++] = 0x00; tx[i++] = 0x00;  /* locktime */

    if (i * 2 + 1 > cap) return 0;
    utils_bin_to_hex(tx, i, out);
    return 1;
}

pc_result pc_channel_open_create(const pc_channel *ch, const char *funding_tx_hex,
                                 char **psbt_hex_out)
{
    if (!ch || !funding_tx_hex || !psbt_hex_out) return PC_ERR_ARG;
    *psbt_hex_out = NULL;

    char txid[65] = {0};
    int vout = 0;
    uint64_t value = 0;
    pc_result r = pc_tx_find_channel_output(ch, funding_tx_hex, txid, &vout, &value);
    if (r != PC_OK) return r;

    char txhex[256];
    if (!unsigned_1in_0out(txid, (uint32_t)vout, txhex, sizeof(txhex)))
        return PC_ERR_PSBT;

    dogecoin_tx *spend = NULL, *funding = NULL;
    dogecoin_psbt *psbt = NULL;
    unsigned char *sbytes = NULL, *fbytes = NULL, *rbytes = NULL;
    pc_result rc = PC_ERR_PSBT;

    size_t slen = 0;
    if (!hex_to_bytes(txhex, &sbytes, &slen)) goto out;
    spend = dogecoin_tx_new();
    if (dogecoin_tx_deserialize(sbytes, slen, spend, NULL) == 0) goto out;

    psbt = dogecoin_psbt_create(spend);
    if (!psbt) goto out;

    size_t flen = 0;
    if (!hex_to_bytes(funding_tx_hex, &fbytes, &flen)) goto out;
    funding = dogecoin_tx_new();
    if (dogecoin_tx_deserialize(fbytes, flen, funding, NULL) == 0) goto out;
    if (!dogecoin_psbt_input_set_utxo(psbt, 0, funding)) goto out;

    size_t rlen = 0;
    if (!hex_to_bytes(ch->redeem_script_hex, &rbytes, &rlen)) goto out;
    if (!dogecoin_psbt_input_set_redeemscript(psbt, 0, rbytes, rlen)) goto out;

    *psbt_hex_out = dogecoin_psbt_to_hex(psbt);
    rc = *psbt_hex_out ? PC_OK : PC_ERR_PSBT;
out:
    free(sbytes); free(fbytes); free(rbytes);
    if (psbt)    dogecoin_psbt_free(psbt);
    if (spend)   dogecoin_tx_free(spend);
    if (funding) dogecoin_tx_free(funding);
    return rc;
}

pc_result pc_channel_open_accept(pc_channel *ch, const char *psbt_hex,
                                 const char *funding_tx_hex,
                                 uint32_t chain_height, uint32_t min_slack,
                                 uint64_t *capacity_out)
{
    if (!ch || !psbt_hex || !funding_tx_hex) return PC_ERR_ARG;
    if (!ch->redeem_script_hex[0]) return PC_ERR_STATE;

    /* A channel that expires while Bob holds a payment is one Alice can refund
       out from under him, so refuse one that does not outlast the work. */
    if ((uint64_t)ch->locktime <= (uint64_t)chain_height + min_slack)
        return PC_ERR_STATE;

    /* Which output funds the channel is derived, not asserted. */
    char txid[65] = {0};
    int vout = 0;
    uint64_t value = 0;
    pc_result r = pc_tx_find_channel_output(ch, funding_tx_hex, txid, &vout, &value);
    if (r != PC_OK) return r;
    if (value == 0) return PC_ERR_AMOUNT;

    dogecoin_psbt *psbt = NULL;
    if (!dogecoin_psbt_from_hex(psbt_hex, &psbt) || !psbt) return PC_ERR_PSBT;

    pc_result rc = PC_ERR_PSBT;
    if (dogecoin_psbt_num_inputs(psbt) != 1) goto out;
    if (dogecoin_psbt_num_outputs(psbt) != 0) goto out;   /* nothing promised yet */
    if (dogecoin_psbt_input_num_partial_sigs(psbt, 0) != 0) goto out;

    /* The redeem script commits Bob's key and the locktime, so matching it
       against the one he computed is what makes the rest of this his channel. */
    size_t rlen = 0;
    unsigned char rbuf[520];
    if (!dogecoin_psbt_input_get_redeemscript(psbt, 0, rbuf, sizeof(rbuf), &rlen)) goto out;
    char rhex[PC_MAX_SCRIPT_HEX];
    if (rlen * 2 + 1 > sizeof(rhex)) goto out;
    utils_bin_to_hex(rbuf, rlen, rhex);
    if (strcmp(rhex, ch->redeem_script_hex) != 0) goto out;

    r = pc_channel_set_funding(ch, txid, vout, value);
    if (r != PC_OK) { rc = r; goto out; }
    if (capacity_out) *capacity_out = value;
    rc = PC_OK;
out:
    if (psbt) dogecoin_psbt_free(psbt);
    return rc;
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
    /* subtract rather than add: to_bob + fee wraps and passes on a hostile
       amount, and the envelope is where such an amount arrives from */
    if (to_bob_koinu == 0 || fee_koinu > ch->capacity_koinu ||
        to_bob_koinu > ch->capacity_koinu - fee_koinu)
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

    /* the _ex form writes where we say. finalize_transaction() returns a static
       buffer shared with every other hex conversion in the library. */
    unsigned_hex = (char *)malloc(DOGECOIN_MAX_TX_HEX_LEN);
    if (!unsigned_hex) goto out;
    if (!finalize_transaction_ex(tix, (char *)bob_addr, fee, total,
                                 (char *)alice_addr,
                                 unsigned_hex, DOGECOIN_MAX_TX_HEX_LEN))
        goto out;

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
    const dogecoin_chainparams *chain = pc_chainparams(ch->chain);
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
    unsigned char rbuf[520];
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
    const dogecoin_chainparams *chain = pc_chainparams(ch->chain);
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
    /* bound the whole assembly before writing any of it, rather than after the
       signatures are already in */
    if (siglen[alice_idx] == 0 || siglen[alice_idx] > 75 ||
        siglen[bob_idx]   == 0 || siglen[bob_idx]   > 75 ||
        rlen == 0 || rlen > 520) goto out;
    size_t pushn = (rlen < 76) ? 1 : 2;
    if (4 + siglen[alice_idx] + siglen[bob_idx] + pushn + rlen > sizeof(ss))
        goto out;

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
    memcpy(ss + n, rbytes, rlen); n += rlen;

    if (!dogecoin_psbt_input_set_final_scriptsig(psbt, 0, ss, n)) goto out;

    *raw_tx_hex_out = dogecoin_psbt_extract_hex(psbt);
    rc = *raw_tx_hex_out ? PC_OK : PC_ERR_PSBT;
out:
    free(rbytes);
    if (psbt) dogecoin_psbt_free(psbt);
    return rc;
}

/* ── Alice: take the money back if Bob goes away ─────────────── */

static size_t put_u(unsigned char *o, uint64_t v, size_t n)
{
    for (size_t i = 0; i < n; i++) o[i] = (unsigned char)((v >> (8 * i)) & 0xff);
    return n;
}

/* Serialize the refund with (ss) as the input's scriptSig, or empty when (ss)
   is NULL, which is the form the signature is taken over. */
static size_t refund_bytes(const pc_channel *ch, const unsigned char h160[20],
                           uint64_t value, const unsigned char *ss, size_t sslen,
                           unsigned char *o)
{
    size_t n = 0;
    n += put_u(o + n, 1, 4);                       /* version */
    o[n++] = 0x01;                                 /* one input */

    /* the txid is stored reversed from the way it is displayed */
    unsigned char txid[32];
    size_t tn = 0;
    utils_hex_to_bin(ch->funding_txid, txid, 64, &tn);
    for (int i = 0; i < 32; i++) o[n + i] = txid[31 - i];
    n += 32;
    n += put_u(o + n, (uint64_t)ch->funding_vout, 4);

    if (ss) {
        if (sslen < 0xfd) o[n++] = (unsigned char)sslen;
        else { o[n++] = 0xfd; n += put_u(o + n, sslen, 2); }
        memcpy(o + n, ss, sslen); n += sslen;
    } else {
        o[n++] = 0x00;
    }

    /* non-final, because CHECKLOCKTIMEVERIFY refuses to run against a final
       input and would let the refund be mined immediately if it did not */
    n += put_u(o + n, 0xfffffffeu, 4);

    o[n++] = 0x01;                                 /* one output */
    n += put_u(o + n, value, 8);
    o[n++] = 25;
    o[n++] = 0x76; o[n++] = 0xa9; o[n++] = 0x14;
    memcpy(o + n, h160, 20); n += 20;
    o[n++] = 0x88; o[n++] = 0xac;

    n += put_u(o + n, ch->locktime, 4);            /* what CLTV checks against */
    return n;
}

pc_result pc_refund_create(const pc_channel *ch,
                           const char *alice_wif,
                           const char *alice_addr,
                           uint64_t fee_koinu,
                           char **raw_tx_hex_out)
{
    if (!ch || !alice_wif || !alice_addr || !raw_tx_hex_out) return PC_ERR_ARG;
    if (!ch->funding_txid[0]) return PC_ERR_STATE;
    if (fee_koinu == 0 || fee_koinu >= ch->capacity_koinu) return PC_ERR_AMOUNT;
    *raw_tx_hex_out = NULL;

    uint8_t decoded[64];
    if (dogecoin_base58_decode_check(alice_addr, decoded, sizeof(decoded)) != 25)
        return PC_ERR_ARG;
    unsigned char h160[20];
    memcpy(h160, decoded + 1, sizeof(h160));

    unsigned char *redeem = NULL;
    size_t rlen = 0;
    if (!hex_to_bytes(ch->redeem_script_hex, &redeem, &rlen)) return PC_ERR_SCRIPT;

    pc_result rc = PC_ERR_PSBT;
    unsigned char *buf = NULL, *ss = NULL;
    char *hex = NULL;
    uint64_t value = ch->capacity_koinu - fee_koinu;

    size_t cap = 256 + rlen * 2;
    buf = (unsigned char *)malloc(cap);
    if (!buf) { rc = PC_ERR_ARG; goto out; }

    /* what the signature covers: the redeem script stands in for the scriptSig */
    size_t un = refund_bytes(ch, h160, value, NULL, 0, buf);
    hex = (char *)malloc(un * 2 + 1);
    if (!hex) { rc = PC_ERR_ARG; goto out; }
    utils_bin_to_hex(buf, un, hex);

    unsigned char hash[32];
    rc = pc_tx_sighash(hex, redeem, rlen, hash);
    if (rc != PC_OK) goto out;
    rc = PC_ERR_PSBT;

    dogecoin_key key;
    dogecoin_privkey_init(&key);
    if (!dogecoin_privkey_decode_wif((char *)alice_wif, pc_chainparams(ch->chain), &key)) {
        rc = PC_ERR_KEY; goto out;
    }
    unsigned char sig[80];
    size_t siglen = sizeof(sig);
    int signed_ok = dogecoin_ecc_sign(key.privkey, hash, sig, &siglen);
    dogecoin_privkey_cleanse(&key);
    if (!signed_ok || siglen == 0 || siglen > 74) goto out;
    sig[siglen++] = 0x01;                          /* SIGHASH_ALL */

    /* <alice sig> OP_1 <redeem script>, where OP_1 takes the IF branch */
    size_t sscap = 2 + siglen + 3 + rlen;
    ss = (unsigned char *)malloc(sscap);
    if (!ss) { rc = PC_ERR_ARG; goto out; }
    size_t sn = 0;
    if (siglen > 75) goto out;
    ss[sn++] = (unsigned char)siglen;
    memcpy(ss + sn, sig, siglen); sn += siglen;
    ss[sn++] = 0x51;                               /* OP_1 */
    if (rlen < 76) ss[sn++] = (unsigned char)rlen;
    else { ss[sn++] = 0x4c; ss[sn++] = (unsigned char)rlen; }
    memcpy(ss + sn, redeem, rlen); sn += rlen;

    size_t fn = refund_bytes(ch, h160, value, ss, sn, buf);

    /* Alice builds this when Bob is already gone, so there is nobody on the
       other end to refuse it and tell her why. Everything Bob would have
       checked about a payment gets checked here instead, which turns a
       discovery at the locktime into a discovery at call time. */
    if (value < PC_HARD_DUST_KOINU) { rc = PC_ERR_AMOUNT; goto out; }
    if (fee_koinu < pc_min_fee(fn, value < PC_SOFT_DUST_KOINU ? 1 : 0)) {
        rc = PC_ERR_AMOUNT; goto out;
    }
    {
        unsigned char apub[33];
        size_t an = 0;
        if (strlen(ch->alice_pubkey_hex) != 66) { rc = PC_ERR_KEY; goto out; }
        utils_hex_to_bin(ch->alice_pubkey_hex, apub, 66, &an);
        if (an != sizeof(apub)) { rc = PC_ERR_KEY; goto out; }
        if (!dogecoin_ecc_verify_sig(apub, true, hash, sig, siglen - 1)) {
            rc = PC_ERR_KEY; goto out;
        }
    }

    /* the caller frees this with dogecoin_free(), which goes through the
       library's mem mapper, so it has to come from dogecoin_malloc() */
    char *outhex = (char *)dogecoin_malloc(fn * 2 + 1);
    if (!outhex) { rc = PC_ERR_ARG; goto out; }
    utils_bin_to_hex(buf, fn, outhex);

    *raw_tx_hex_out = outhex;
    rc = PC_OK;
out:
    free(hex);
    free(ss);
    free(buf);
    free(redeem);
    return rc;
}
