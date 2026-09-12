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
#include "hex.h"

/* koinu crypto: the sha256/hash160, ec verify, and base58 this file needs.
   koinu's crypto/hex.h is not included; pc uses its own. */
#include "sha2.h"
#include "ripemd160.h"
#include "ec.h"
#include "base58.h"

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
   mined, which is the same failure as not checking at all and harder to see.

   The surcharge is on the relay floor only, not the block floor: GetDogecoinDustFee
   is added in GetDogecoinMinRelayFee (dogecoin-fees.cpp) and the wallet's own
   pay target (wallet.cpp), while the miner tests packageFees against a bare
   blockMinFeeRate.GetFee (miner.cpp), so max(relay + surcharge, block) is the
   pair of floors and the block term is right to omit it. */
#define PC_RELAY_KOINU_PER_KB   100000ULL   /* DEFAULT_MIN_RELAY_TX_FEE   */
#define PC_BLOCK_KOINU_PER_KB  1000000ULL   /* DEFAULT_BLOCK_MIN_TX_FEE   */

/* CFeeRate::GetFee(), which is proportional rather than per started kB.
 *
 * The multiply is bounded first. pc_doge_to_koinu accepts anything up to
 * PC_MAX_MONEY_KOINU, so a rate off a backend can be large enough that
 * per_kb * bytes wraps, and the interesting wraps land near zero rather than
 * near the top: the guard below would turn one into 1 koinu, max() against the
 * policy floor would turn that into an ordinary-looking fee, and the ceiling
 * that exists to refuse exactly this would never fire because the number came
 * out small. Saturating sends it the other way, into the refusal. */
static uint64_t fee_at(uint64_t per_kb, size_t bytes)
{
    if (bytes && per_kb > UINT64_MAX / (uint64_t)bytes) return UINT64_MAX;
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

uint64_t pc_fee_for_feerate(uint64_t koinu_per_kb, size_t txbytes)
{
    return fee_at(koinu_per_kb, txbytes);
}

/* The 0xff case is unreachable from here, since every caller passes a script of
   at most 520 bytes, but leaving it out made a length at or above 2^32 encode
   as a truncated 0xfe rather than refuse. Silently wrong is the wrong direction
   for something feeding a consensus digest. */
static size_t put_varint(unsigned char *out, uint64_t v)
{
    if (v < 0xfd)   { out[0] = (unsigned char)v; return 1; }
    if (v <= 0xffff) {
        out[0] = 0xfd; out[1] = v & 0xff; out[2] = (v >> 8) & 0xff; return 3;
    }
    if (v <= 0xffffffffULL) {
        out[0] = 0xfe;
        out[1] = v & 0xff;         out[2] = (v >> 8) & 0xff;
        out[3] = (v >> 16) & 0xff; out[4] = (v >> 24) & 0xff;
        return 5;
    }
    out[0] = 0xff;
    for (int i = 0; i < 8; i++) out[1 + i] = (unsigned char)((v >> (8 * i)) & 0xff);
    return 9;
}

/* Read one plain data push, refusing anything else. The scriptSig this channel
   builds is pushes and OP_0 only, so an opcode here means it is not ours.

   The push has to be the shortest encoding of its length, which is
   SCRIPT_VERIFY_MINIMALDATA and is in the standard flag set. Without that a
   71-byte signature pushed through OP_PUSHDATA1 parses here and is non-standard
   on the wire: accepted by Bob, refused by every node he offers it to. pc's own
   assembly is already minimal, using PUSHDATA1 only for the 116-byte redeem
   script, so this refuses nothing pc builds. */
static int rd_push(const unsigned char *p, size_t len, size_t *off,
                   const unsigned char **out, size_t *outlen)
{
    if (*off >= len) return 0;
    unsigned char op = p[*off];
    size_t n;
    if (op >= 1 && op <= 75)  { n = op; *off += 1; }
    else if (op == 0x4c) {
        if (*off + 2 > len) return 0;
        n = p[*off + 1];
        if (n < 76) return 0;                     /* a direct push would do */
        *off += 2;
    } else return 0;
    if (*off + n > len) return 0;
    *out = p + *off; *outlen = n; *off += n;
    return 1;
}

/* Half the secp256k1 group order, big-endian. A signature above it is the
   other valid encoding of the same signature. */
static const unsigned char SECP256K1_HALF_N[32] = {
    0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0x5d,0x57,0x6e,0x73,0x57,0xa4,0x50,0x1d,0xdf,0xe9,0x2f,0x46,0x68,0x1b,0x20,0xa0
};

/* Whether a DER signature, without its trailing hashtype byte, is one a default
   node would relay: strictly encoded per BIP66, and low-S per
   SCRIPT_VERIFY_LOW_S. Both are in the standard flag set.
 *
 * A high-S signature verifies perfectly well. It is the same signature with S
 * replaced by (n - S), which anyone can compute from a valid one without a key,
 * and it is refused by a default node as non-standard. Bob acking one leaves
 * him holding a newest state nothing will relay, which is the failure the fee
 * floor comment describes: worse than not checking, because it looks fine.
 *
 * koinu's kw_ec_verify enforces both today, so this is belt and braces. It is
 * here because the promise is pc's: "what Bob acks, a default node would accept
 * and mine" should not quietly become a property of whichever library is
 * linked. Refusing something valid is the safe direction, and this matches the
 * filter that selected the 156 mainnet vectors, every one of which passes. */
pc_result pc_sig_is_standard(const unsigned char *der, size_t dlen)
{
    if (dlen < 8 || dlen > 72)              return PC_ERR_PSBT;
    if (der[0] != 0x30 || der[1] != dlen - 2) return PC_ERR_PSBT;
    if (der[2] != 0x02)                     return PC_ERR_PSBT;

    size_t lenr = der[3];
    if (lenr == 0 || 6 + lenr > dlen)       return PC_ERR_PSBT;
    if (der[4] & 0x80)                      return PC_ERR_PSBT;   /* negative */
    if (lenr > 1 && der[4] == 0x00 && !(der[5] & 0x80)) return PC_ERR_PSBT;

    size_t poss = 4 + lenr;
    if (der[poss] != 0x02)                  return PC_ERR_PSBT;
    size_t lens = der[poss + 1];
    if (lens == 0 || poss + 2 + lens != dlen) return PC_ERR_PSBT;
    const unsigned char *s = der + poss + 2;
    if (s[0] & 0x80)                        return PC_ERR_PSBT;
    if (lens > 1 && s[0] == 0x00 && !(s[1] & 0x80)) return PC_ERR_PSBT;

    /* S has to fit in 32 bytes before it can be compared against half the group
       order, and the checks above do not establish that. They say S is positive
       and carries no redundant leading zero, which still admits a 33-byte S
       whose first byte is 0x01 through 0x7f: positive, not redundant, and
       larger than any scalar. Dropping that byte as though it were a pad
       compares the low 32 bytes of a number above 2^256 and calls it low.
     *
     * Core refuses these too, just not in IsValidSignatureEncoding: its strict
     * DER pass lets them by and secp256k1_ecdsa_signature_parse_der fails on
     * the overflow afterwards. pc has no second pass, so the magnitude decision
     * belongs here rather than with whatever verifier runs next. */
    if (lens > 33 || (lens == 33 && s[0] != 0x00)) return PC_ERR_PSBT;

    unsigned char s32[32];
    memset(s32, 0, sizeof(s32));
    size_t n = lens, off = 0;
    if (n == 33) { n = 32; off = 1; }       /* the pad, now known to be one */
    memcpy(s32 + (32 - n), s + off, n);
    if (memcmp(s32, SECP256K1_HALF_N, 32) > 0) return PC_ERR_PSBT;
    return PC_OK;
}

/* The legacy SIGHASH_ALL digest for the one input, with (script_code) standing
   in where the scriptSig sits.

   (script_code) is spliced in whole. A real signer removes everything up to and
   including the last OP_CODESEPARATOR first, so this is only correct for
   scripts that contain none. The channel's redeem script does not, and the
   signature is deterministic given the script, but the signature here is
   general enough to be handed one that does. Do not reuse it for that.

   koinu's kw_tx_signature computes the same digest and pc now signs through it,
   but this stays a second, independent implementation of a consensus-critical
   digest. The guard against the two drifting is that verify_sigs() checks Bob's
   own signature against this hash as well as Alice's: his came from koinu's
   signer, so if this ever stops agreeing with it the honest path fails on the
   next payment rather than a forgery passing quietly. Do not drop that check to
   save a verify. */
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
    kw_sha256(buf, o, h1);
    kw_sha256(h1, sizeof(h1), out);
    free(buf);
    return 1;
}

/* Both signatures are checked, not just Alice's. Bob's came from koinu's
   signer, so a digest that verifies his verifies that this computation agrees
   with the one that produced it, and a mistake here fails on the honest path
   instead of passing a forgery. */
static pc_result verify_sigs(const pc_channel *ch,
                             const unsigned char *tx, size_t txlen,
                             size_t sig_start, size_t sig_end,
                             const unsigned char *ss, size_t sslen)
{
    /* 256, not the 520 P2SH allows. rd_push() reads a direct push or
       OP_PUSHDATA1, so a redeem script over 255 bytes cannot appear in a
       scriptSig this reads at all, and a buffer sized past that advertises a
       limit the parser opposite it cannot reach. Raising this means adding
       OP_PUSHDATA2 there first. */
    unsigned char redeem[256];
    size_t rlen = 0;
    size_t rhexlen = strlen(ch->redeem_script_hex);
    if (rhexlen == 0 || (rhexlen % 2) || rhexlen / 2 > 255 ||
        !pc_is_hex(ch->redeem_script_hex, rhexlen))
        return PC_ERR_SCRIPT;
    if (!pc_hex_to_bin(ch->redeem_script_hex, redeem, rhexlen / 2)) return PC_ERR_SCRIPT;
    rlen = rhexlen / 2;

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
    if (!pc_hex_to_bin(ch->alice_pubkey_hex, apub, sizeof(apub))) return PC_ERR_KEY;
    if (!pc_hex_to_bin(ch->bob_pubkey_hex, bpub, sizeof(bpub))) return PC_ERR_KEY;

    /* Standard before valid: a high-S or loosely encoded signature verifies,
       and is refused by the network Bob has to hand this to. */
    if (pc_sig_is_standard(sa, salen - 1) != PC_OK) return PC_ERR_PSBT;
    if (pc_sig_is_standard(sb, sblen - 1) != PC_OK) return PC_ERR_PSBT;

    if (!kw_ec_verify(apub, hash, sa, salen - 1))
        return PC_ERR_PSBT;
    if (!kw_ec_verify(bpub, hash, sb, sblen - 1))
        return PC_ERR_PSBT;
    return PC_OK;
}

/* IsStandardTx refuses a transaction whose version is outside 1..2 and one
   carrying any output whose script is not a standard type. Bob checks the
   output paying him and had nothing to say about either, so Alice could sign an
   honest-looking payment that no node would relay and he would ack it.

   Narrower than the policy it mirrors: IsStandard also takes bare pubkey, bare
   multisig up to three keys and a single OP_RETURN. A channel has no reason to
   pay any of those, and refusing what it cannot be sure of is the safe
   direction for the party who ships the goods. */
#define PC_TX_VERSION_MIN 1u
#define PC_TX_VERSION_MAX 2u

static int standard_spk(const unsigned char *spk, size_t len)
{
    if (len == 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 0x14 &&
        spk[23] == 0x88 && spk[24] == 0xac) return 1;          /* p2pkh */
    if (len == 23 && spk[0] == 0xa9 && spk[1] == 0x14 &&
        spk[22] == 0x87) return 1;                              /* p2sh  */
    return 0;
}

/* The scriptPubKey a P2SH address stands for: base58check gives back a version
   byte and the 20-byte script hash, so no hashing is needed to rebuild it. */
static int p2sh_script_for(const pc_channel *ch, unsigned char out[23])
{
    uint8_t raw[64];
    /* the checked payload is the version byte and the 20-byte script hash */
    size_t n = 0;
    if (!kw_base58check_decode(ch->p2sh_address, raw, sizeof(raw), &n) || n != 21)
        return 0;
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
    if (!pc_hex_to_bin(raw_tx_hex, buf, hl / 2)) { free(buf); return PC_ERR_ARG; }
    size_t blen = hl / 2;

    /* held until the walk finishes, so a refusal leaves the caller's outputs
       alone rather than filled in from a call that failed */
    int found_vout = 0;
    uint64_t found_value = 0;

    pc_result rc = PC_ERR_PSBT;

    /* txid = double-SHA256 of the whole serialization, in display (reversed)
       order. A dogecoin transaction is legacy, so the txid is the hash of
       exactly these bytes; no deserialize-and-reserialize is needed. The walk
       below is what rejects a malformed transaction. */
    {
        unsigned char h1[32], h2[32], disp[32];
        kw_sha256(buf, blen, h1);
        kw_sha256(h1, sizeof(h1), h2);
        for (int i = 0; i < 32; i++) disp[i] = h2[31 - i];
        if (txid_out) pc_bin_to_hex(disp, 32, txid_out);
    }

    /* walk the outputs for the one paying this channel */
    {
        rdr r = { buf, blen, 0, 0 };
        rd_u(&r, 4);
        uint64_t nin = rd_varint(&r);
        for (uint64_t i = 0; i < nin && !r.bad; i++) {
            /* before advancing, not after. need(&r, 0) afterwards catches the
               same overrun, but only because a zero-length check still compares
               off against len, which is a subtlety a reader has to notice. */
            need(&r, 36);
            if (r.bad) break;
            r.off += 36;
            rd_script(&r, NULL, NULL);
            rd_u(&r, 4);
        }
        uint64_t nout = rd_varint(&r);
        /* the same bound the payment reader uses. it terminates either way,
           since every iteration consumes bytes, but two walkers over
           peer-supplied bytes disagreeing about their limits is where the next
           one goes wrong */
        if (r.bad || nout == 0 || nout > PC_MAX_OUTPUTS) goto out;
        rc = PC_ERR_AMOUNT;
        for (uint64_t i = 0; i < nout; i++) {
            uint64_t value = rd_u(&r, 8);
            const unsigned char *spk = NULL;
            size_t spklen = 0;
            rd_script(&r, &spk, &spklen);
            if (r.bad) { rc = PC_ERR_PSBT; goto out; }
            if (value > PC_MAX_MONEY_KOINU) { rc = PC_ERR_AMOUNT; goto out; }
            if (spklen == sizeof(want) && memcmp(spk, want, sizeof(want)) == 0) {
                /* two outputs paying the channel means the capacity is not a
                   fact about the transaction, so refuse rather than pick.
                   Held locally until the walk finishes: writing through on the
                   first match and then refusing on the second leaves the caller
                   with values from a call that failed. */
                if (rc == PC_OK) { rc = PC_ERR_AMOUNT; goto out; }
                found_vout  = (int)i;
                found_value = value;
                rc = PC_OK;
            }
        }
        /* The whole transaction, or none of it. The txid above is the hash of
           every byte in the buffer, so a transaction with anything appended
           parses here and is recorded under the hash of the padded
           serialization rather than of the transaction. The payment reader has
           made this check since it was written; two walkers over peer-supplied
           bytes disagreeing about their limits is the case the comment above
           already names. */
        rd_u(&r, 4);                                  /* locktime */
        if (r.bad || r.off != r.len) { rc = PC_ERR_PSBT; goto out; }
    }
out:
    if (rc == PC_OK) {
        if (vout_out)  *vout_out  = found_vout;
        if (value_out) *value_out = found_value;
    }
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
    unsigned char bpub[33];
    if (!pc_hex_to_bin(ch->bob_pubkey_hex, bpub, 33)) return PC_ERR_ARG;
    uint8_t bob_h160[20];
    kw_hash160(bpub, 33, bob_h160);

    unsigned char want[25];
    want[0] = 0x76; want[1] = 0xa9; want[2] = 0x14;
    memcpy(want + 3, bob_h160, 20);
    want[23] = 0x88; want[24] = 0xac;

    size_t hl = strlen(raw_tx_hex);
    if (hl == 0 || (hl % 2)) return PC_ERR_ARG;
    unsigned char *buf = (unsigned char *)malloc(hl / 2 + 1);
    if (!buf) return PC_ERR_ARG;
    if (!pc_hex_to_bin(raw_tx_hex, buf, hl / 2)) { free(buf); return PC_ERR_ARG; }
    size_t blen = hl / 2;

    rdr r = { buf, blen, 0, 0 };
    pc_result rc = PC_ERR_PSBT;

    uint32_t version = (uint32_t)rd_u(&r, 4);
    if (r.bad) goto out;
    if (version < PC_TX_VERSION_MIN || version > PC_TX_VERSION_MAX) {
        rc = PC_ERR_VERSION; goto out;
    }

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
    pc_bin_to_hex(disp, 32, txid);
    if (strcmp(txid, ch->funding_txid) != 0)      goto out;
    if (vout != (uint32_t)ch->funding_vout)       goto out;

    uint64_t nout = rd_varint(&r);
    if (r.bad || nout == 0 || nout > PC_MAX_OUTPUTS) goto out;

    uint64_t to_bob = 0, total = 0;
    size_t soft_dust = 0;
    for (uint64_t i = 0; i < nout; i++) {
        uint64_t value = rd_u(&r, 8);
        const unsigned char *spk = NULL;
        size_t spklen = 0;
        rd_script(&r, &spk, &spklen);
        if (r.bad) goto out;

        /* every output, not only the one paying Bob: one non-standard script
           anywhere makes the whole transaction unrelayable */
        if (!standard_spk(spk, spklen)) { rc = PC_ERR_NONSTANDARD; goto out; }

        if (value > PC_MAX_MONEY_KOINU) { rc = PC_ERR_CAPACITY; goto out; }

        /* Bound the output before adding it, not the sum afterwards. value is a
           full 64-bit read off the wire, so an honestly signed payment carrying
           one output of 0xFFFFFFFFFFFFFFFF and a second tuned to suit wraps
           total back under the capacity while to_bob stays enormous: every
           check below then passes and Bob ships against a transaction no node
           will accept. Per output this is also the stronger statement, since
           nothing that went in can come out larger. */
        if (value > ch->capacity_koinu) { rc = PC_ERR_CAPACITY; goto out; }
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
    /* Equal, not at least. The ratchet stores the claim and Bob reports the
       claim, so a payment quietly paying more was recorded as the smaller
       number and the next one could replace it with a transaction paying less
       than that one really did. Nothing Bob invoiced was ever at risk, since
       the claim is what he checked against, but "paid N koinu held" should be
       the transaction he is holding and costs nothing to require. */
    if (to_bob != claimed_to_bob_koinu) { rc = PC_ERR_AMOUNT; goto out; }
    /* and what is left over has to be enough for a miner to take it */
    if (ch->capacity_koinu - total < pc_min_fee(blen, soft_dust)) {
        rc = PC_ERR_FEE; goto out;
    }
    /* and not so much that a node refuses to relay it at all. Bob's promise is
       that this would be accepted and mined by a default node, and one paying
       over DEFAULT_TRANSACTION_MAXFEE is rejected as absurdly-high-fee before
       it reaches a miner, so accepting it would break that promise in the
       direction the floor check covers at the other end. */
    if (ch->capacity_koinu - total > PC_MAX_FEE_KOINU) {
        rc = PC_ERR_FEE_HIGH; goto out;
    }

    rc = verify_sigs(ch, buf, blen, sig_start, sig_end, ss, sslen);
out:
    free(buf);
    return rc;
}

/* Only correct for a (script_code) with no OP_CODESEPARATOR; see sighash_all. */
pc_result pc_tx_sighash(const char *raw_tx_hex,
                        const unsigned char *script_code, size_t sclen,
                        unsigned char out[32])
{
    if (!raw_tx_hex || !script_code || !out) return PC_ERR_ARG;
    size_t hl = strlen(raw_tx_hex);
    if (hl == 0 || (hl % 2)) return PC_ERR_ARG;
    unsigned char *buf = (unsigned char *)malloc(hl / 2 + 1);
    if (!buf) return PC_ERR_ARG;
    size_t blen = hl / 2;

    pc_result rc = PC_ERR_ARG;
    if (!pc_hex_to_bin(raw_tx_hex, buf, blen)) goto out;
    rc = PC_ERR_PSBT;

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
