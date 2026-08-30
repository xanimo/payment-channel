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

/* Dogecoin's fee and dust policy, from src/policy/policy.h and
   src/dogecoin-fees.cpp. A payment has to clear two separate floors. A node
   relays it at DEFAULT_MIN_RELAY_TX_FEE per kB plus a full DEFAULT_DUST_LIMIT
   surcharge for every output under the soft dust limit, and a
   default-configured miner only includes it at DEFAULT_BLOCK_MIN_TX_FEE per kB,
   which is ten times the relay rate and carries no surcharge. Checking only the
   relay floor accepts a payment that propagates, sits in mempools and is never
   mined, which is the same failure as not checking at all and harder to see. */
#define PC_RELAY_KOINU_PER_KB   100000ULL   /* DEFAULT_MIN_RELAY_TX_FEE   */
#define PC_BLOCK_KOINU_PER_KB  1000000ULL   /* DEFAULT_BLOCK_MIN_TX_FEE   */

/* CFeeRate::GetFee(), which is proportional rather than per started kB */
static uint64_t fee_at(uint64_t per_kb, size_t bytes)
{
    uint64_t f = per_kb * (uint64_t)bytes / 1000;
    return (f == 0 && bytes) ? 1 : f;
}

uint64_t pc_min_fee(size_t txbytes, size_t soft_dust_outputs)
{
    uint64_t relay = fee_at(PC_RELAY_KOINU_PER_KB, txbytes)
                   + (uint64_t)soft_dust_outputs * PC_SOFT_DUST_KOINU;
    uint64_t block = fee_at(PC_BLOCK_KOINU_PER_KB, txbytes);
    return relay > block ? relay : block;
}

static size_t put_varint(unsigned char *out, uint64_t v)
{
    if (v < 0xfd)   { out[0] = (unsigned char)v; return 1; }
    if (v <= 0xffff) {
        out[0] = 0xfd; out[1] = v & 0xff; out[2] = (v >> 8) & 0xff; return 3;
    }
    out[0] = 0xfe;
    out[1] = v & 0xff;        out[2] = (v >> 8) & 0xff;
    out[3] = (v >> 16) & 0xff; out[4] = (v >> 24) & 0xff;
    return 5;
}

/* Read one plain data push, refusing anything else. The scriptSig this channel
   builds is pushes and OP_0 only, so an opcode here means it is not ours. */
static int rd_push(const unsigned char *p, size_t len, size_t *off,
                   const unsigned char **out, size_t *outlen)
{
    if (*off >= len) return 0;
    unsigned char op = p[*off];
    size_t n;
    if (op >= 1 && op <= 75)  { n = op; *off += 1; }
    else if (op == 0x4c) {
        if (*off + 2 > len) return 0;
        n = p[*off + 1]; *off += 2;
    } else return 0;
    if (*off + n > len) return 0;
    *out = p + *off; *outlen = n; *off += n;
    return 1;
}

/* The legacy SIGHASH_ALL digest for the one input, with (script_code) standing
   in where the scriptSig sits.

   dogecoin_tx_sighash() computes the same thing and is LIBDOGECOIN_API, but it
   is declared in tx.h, which include_HEADERS does not install, so it cannot be
   called from what libdogecoin ships. This is a second implementation of a
   consensus-critical digest and it stays one, so the guard against the two
   drifting is that verify_sigs() checks Bob's own signature against this hash
   as well as Alice's. His came from libdogecoin's signer, so if this ever stops
   agreeing with theirs the honest path fails on the next payment rather than a
   forgery passing quietly. Do not drop that check to save a verify. */
static int sighash_all(const unsigned char *tx, size_t txlen,
                       size_t sig_start, size_t sig_end,
                       const unsigned char *script_code, size_t sclen,
                       unsigned char out[32])
{
    if (sig_start > sig_end || sig_end > txlen) return 0;
    unsigned char lenbuf[9];
    size_t lenn = put_varint(lenbuf, sclen);
    size_t post = txlen - sig_end;
    size_t n = sig_start + lenn + sclen + post + 4;
    unsigned char *buf = (unsigned char *)malloc(n);
    if (!buf) return 0;

    size_t o = 0;
    memcpy(buf + o, tx, sig_start);            o += sig_start;
    memcpy(buf + o, lenbuf, lenn);             o += lenn;
    memcpy(buf + o, script_code, sclen);       o += sclen;
    memcpy(buf + o, tx + sig_end, post);       o += post;
    buf[o++] = 0x01; buf[o++] = 0x00; buf[o++] = 0x00; buf[o++] = 0x00;

    unsigned char h1[32];
    sha256_raw(buf, o, h1);
    sha256_raw(h1, sizeof(h1), out);
    free(buf);
    return 1;
}

/* Both signatures are checked, not just Alice's. Bob's came from libdogecoin's
   signer, so a digest that verifies his verifies that this computation agrees
   with the one that produced it, and a mistake here fails on the honest path
   instead of passing a forgery. */
static pc_result verify_sigs(const pc_channel *ch,
                             const unsigned char *tx, size_t txlen,
                             size_t sig_start, size_t sig_end,
                             const unsigned char *ss, size_t sslen)
{
    unsigned char redeem[520];
    size_t rlen = 0;
    size_t rhexlen = strlen(ch->redeem_script_hex);
    if (rhexlen == 0 || (rhexlen % 2) || rhexlen / 2 > sizeof(redeem))
        return PC_ERR_SCRIPT;
    utils_hex_to_bin(ch->redeem_script_hex, redeem, rhexlen, &rlen);
    if (rlen != rhexlen / 2) return PC_ERR_SCRIPT;

    /* OP_0 <sig alice> <sig bob> OP_0 <redeem script> */
    size_t off = 0;
    if (off >= sslen || ss[off] != 0x00) return PC_ERR_PSBT;
    off++;
    const unsigned char *sa = NULL, *sb = NULL, *rs = NULL;
    size_t salen = 0, sblen = 0, rslen = 0;
    if (!rd_push(ss, sslen, &off, &sa, &salen)) return PC_ERR_PSBT;
    if (!rd_push(ss, sslen, &off, &sb, &sblen)) return PC_ERR_PSBT;
    if (off >= sslen || ss[off] != 0x00) return PC_ERR_PSBT;
    off++;
    if (!rd_push(ss, sslen, &off, &rs, &rslen)) return PC_ERR_PSBT;
    if (off != sslen) return PC_ERR_PSBT;

    /* the script it commits to must be this channel's */
    if (rslen != rlen || memcmp(rs, redeem, rlen) != 0) return PC_ERR_SCRIPT;

    /* each signature carries its hashtype as a trailing byte */
    if (salen < 2 || sblen < 2) return PC_ERR_PSBT;
    if (sa[salen - 1] != 0x01 || sb[sblen - 1] != 0x01) return PC_ERR_PSBT;

    unsigned char hash[32];
    if (!sighash_all(tx, txlen, sig_start, sig_end, redeem, rlen, hash))
        return PC_ERR_PSBT;

    unsigned char apub[33], bpub[33];
    size_t n = 0;
    if (strlen(ch->alice_pubkey_hex) != 66 || strlen(ch->bob_pubkey_hex) != 66)
        return PC_ERR_KEY;
    utils_hex_to_bin(ch->alice_pubkey_hex, apub, 66, &n);
    if (n != sizeof(apub)) return PC_ERR_KEY;
    utils_hex_to_bin(ch->bob_pubkey_hex, bpub, 66, &n);
    if (n != sizeof(bpub)) return PC_ERR_KEY;

    if (!dogecoin_ecc_verify_sig(apub, true, hash, (unsigned char *)sa, salen - 1))
        return PC_ERR_PSBT;
    if (!dogecoin_ecc_verify_sig(bpub, true, hash, (unsigned char *)sb, sblen - 1))
        return PC_ERR_PSBT;
    return PC_OK;
}

/* The scriptPubKey a P2SH address stands for: base58check gives back a version
   byte and the 20-byte script hash, so no hashing is needed to rebuild it. */
static int p2sh_script_for(const pc_channel *ch, unsigned char out[23])
{
    uint8_t raw[64];
    /* returns the payload plus the 4 checksum bytes it just verified, so a
       21-byte version+hash160 comes back as 25 */
    size_t n = dogecoin_base58_decode_check(ch->p2sh_address, raw, sizeof(raw));
    if (n != 25) return 0;
    out[0] = 0xa9; out[1] = 0x14;
    memcpy(out + 2, raw + 1, 20);
    out[22] = 0x87;
    return 1;
}

pc_result pc_tx_find_channel_output(const pc_channel *ch, const char *raw_tx_hex,
                                    char txid_out[65], int *vout_out,
                                    uint64_t *value_out)
{
    if (!ch || !raw_tx_hex) return PC_ERR_ARG;
    if (!ch->p2sh_address[0]) return PC_ERR_STATE;

    unsigned char want[23];
    if (!p2sh_script_for(ch, want)) return PC_ERR_SCRIPT;

    size_t hl = strlen(raw_tx_hex);
    if (hl == 0 || (hl % 2)) return PC_ERR_ARG;
    unsigned char *buf = (unsigned char *)malloc(hl / 2 + 1);
    if (!buf) return PC_ERR_ARG;
    size_t blen = 0;
    utils_hex_to_bin(raw_tx_hex, buf, hl, &blen);
    if (blen != hl / 2) { free(buf); return PC_ERR_ARG; }

    /* txid over the whole serialization, in display order */
    dogecoin_tx *tx = dogecoin_tx_new();
    pc_result rc = PC_ERR_PSBT;
    if (!tx) { free(buf); return PC_ERR_PSBT; }
    if (dogecoin_tx_deserialize(buf, blen, tx, NULL) == 0) goto out;
    {
        uint256_t h;
        dogecoin_tx_hash(tx, h);
        unsigned char disp[32];
        for (int i = 0; i < 32; i++) disp[i] = h[31 - i];
        if (txid_out) utils_bin_to_hex(disp, 32, txid_out);
    }

    /* walk the outputs for the one paying this channel */
    {
        rdr r = { buf, blen, 0, 0 };
        rd_u(&r, 4);
        uint64_t nin = rd_varint(&r);
        for (uint64_t i = 0; i < nin && !r.bad; i++) {
            r.off += 36;
            need(&r, 0);
            rd_script(&r, NULL, NULL);
            rd_u(&r, 4);
        }
        uint64_t nout = rd_varint(&r);
        if (r.bad || nout == 0) goto out;
        rc = PC_ERR_AMOUNT;
        for (uint64_t i = 0; i < nout; i++) {
            uint64_t value = rd_u(&r, 8);
            const unsigned char *spk = NULL;
            size_t spklen = 0;
            rd_script(&r, &spk, &spklen);
            if (r.bad) { rc = PC_ERR_PSBT; goto out; }
            if (spklen == sizeof(want) && memcmp(spk, want, sizeof(want)) == 0) {
                /* two outputs paying the channel means the capacity is not a
                   fact about the transaction, so refuse rather than pick */
                if (rc == PC_OK) { rc = PC_ERR_AMOUNT; goto out; }
                if (vout_out)  *vout_out  = (int)i;
                if (value_out) *value_out = value;
                rc = PC_OK;
            }
        }
    }
out:
    dogecoin_tx_free(tx);
    free(buf);
    return rc;
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
    size_t sig_start = r.off;
    const unsigned char *ss = NULL;
    size_t sslen = 0;
    rd_script(&r, &ss, &sslen);                   /* scriptSig */
    size_t sig_end = r.off;
    uint32_t sequence = (uint32_t)rd_u(&r, 4);
    if (r.bad) goto out;

    /* Nothing in the ELSE branch executes CLTV, so the script does not
       constrain either field. A non-final input or a future locktime is a
       transaction no node will mine until then, which is money that arrives
       whenever Alice chose rather than now. */
    if (sequence != 0xffffffffu) { rc = PC_ERR_FINAL; goto out; }

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
    size_t soft_dust = 0;
    for (uint64_t i = 0; i < nout; i++) {
        uint64_t value = rd_u(&r, 8);
        const unsigned char *spk = NULL;
        size_t spklen = 0;
        rd_script(&r, &spk, &spklen);
        if (r.bad) goto out;
        total += value;

        /* IsStandardTx refuses the whole transaction for a single output under
           the hard limit, so one dusty change output makes the newest state
           worthless and Bob has to fall back to an older one.

           This is deliberately stricter than the policy it mirrors. IsDust()
           exempts unspendable outputs, and an honest Alice never builds one, but
           what arrives on the socket is not bound by what she builds: a hostile
           one can attach a zero-value OP_RETURN a node would accept and this
           refuses. Refusing is the safe direction, so the difference stands. */
        if (value < PC_HARD_DUST_KOINU) { rc = PC_ERR_DUST; goto out; }
        if (value < PC_SOFT_DUST_KOINU) soft_dust++;

        if (spklen == sizeof(want) && memcmp(spk, want, sizeof(want)) == 0)
            to_bob += value;
    }
    uint32_t locktime = (uint32_t)rd_u(&r, 4);
    if (r.bad) goto out;
    if (r.off != r.len) goto out;                 /* trailing bytes: not our tx */
    if (locktime != 0) { rc = PC_ERR_FINAL; goto out; }

    /* The fee is capacity minus what the outputs spend, so an input that does
       not cover the outputs would be a transaction no node will relay. */
    if (total > ch->capacity_koinu) { rc = PC_ERR_CAPACITY; goto out; }
    if (to_bob < claimed_to_bob_koinu) { rc = PC_ERR_AMOUNT; goto out; }
    /* and what is left over has to be enough for a miner to take it */
    if (ch->capacity_koinu - total < pc_min_fee(blen, soft_dust)) {
        rc = PC_ERR_FEE; goto out;
    }

    rc = verify_sigs(ch, buf, blen, sig_start, sig_end, ss, sslen);
out:
    free(buf);
    return rc;
}

pc_result pc_tx_sighash(const char *raw_tx_hex,
                        const unsigned char *script_code, size_t sclen,
                        unsigned char out[32])
{
    if (!raw_tx_hex || !script_code || !out) return PC_ERR_ARG;
    size_t hl = strlen(raw_tx_hex);
    if (hl == 0 || (hl % 2)) return PC_ERR_ARG;
    unsigned char *buf = (unsigned char *)malloc(hl / 2 + 1);
    if (!buf) return PC_ERR_ARG;
    size_t blen = 0;
    utils_hex_to_bin(raw_tx_hex, buf, hl, &blen);

    pc_result rc = PC_ERR_PSBT;
    if (blen != hl / 2) goto out;

    rdr r = { buf, blen, 0, 0 };
    rd_u(&r, 4);                                  /* version */
    if (rd_varint(&r) != 1 || r.bad) goto out;    /* the channel spends one */
    need(&r, 36);
    if (r.bad) goto out;
    r.off += 36;                                  /* outpoint */
    size_t s0 = r.off;
    rd_script(&r, NULL, NULL);
    size_t s1 = r.off;
    if (r.bad) goto out;

    if (!sighash_all(buf, blen, s0, s1, script_code, sclen, out)) goto out;
    rc = PC_OK;
out:
    free(buf);
    return rc;
}
