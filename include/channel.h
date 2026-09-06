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

#ifndef PAYMENT_CHANNEL_H
#define PAYMENT_CHANNEL_H

#include <dogecoin/libdogecoin.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A unidirectional channel. Alice funds a 2-of-2 P2SH and sends Bob a
 * progressively larger payment as a partially signed transaction; Bob holds
 * them and broadcasts only the last. Bob broadcasting an earlier state pays
 * himself less, so no revocation is needed and the scheme is safe on a chain
 * without SegWit, provided the funding transaction is confirmed before any
 * payment referencing it is signed. See doc/PROTOCOL.md. */

/* Which chain. Not a boolean: regtest and testnet share a p2sh prefix but not a
 * p2pkh one (0x6f against 0x71), so a two-state flag prints addresses a regtest
 * node does not recognise even though the scripts are identical. */
typedef enum { PC_CHAIN_MAIN = 0, PC_CHAIN_TEST, PC_CHAIN_REGTEST } pc_chain;

const dogecoin_chainparams *pc_chainparams(pc_chain chain);

/* 511 bytes of script as hex plus a NUL. P2SH allows 520, so a maximal legal
   redeem script does not fit here and pc_refund_create() refuses over 255
   anyway, which is the tighter of the two limits. */
#define PC_MAX_SCRIPT_HEX   1024
#define PC_MAX_PSBT_HEX    16384
#define PC_ADDR_LEN        P2SHLEN

typedef enum {
    PC_OK = 0,
    PC_ERR_ARG,          /* a caller argument was missing or malformed        */
    PC_ERR_KEY,          /* a WIF key would not decode                        */
    PC_ERR_SCRIPT,       /* the redeem script would not build or hash         */
    PC_ERR_PSBT,         /* a PSBT would not parse, sign, or finalize         */
    PC_ERR_STATE,        /* the channel is not in a state that allows this    */
    PC_ERR_AMOUNT,       /* it pays Bob less than it claims to                */
    PC_ERR_CAPACITY,     /* its outputs spend more than the channel holds     */
    PC_ERR_DUST,         /* an output is under the hard dust limit            */
    PC_ERR_FEE,          /* what is left over is below the miner's floor      */
    PC_ERR_FINAL,        /* a non-zero locktime or a non-final input          */
    PC_ERR_VERSION,      /* the transaction version is outside 1..2            */
    PC_ERR_NONSTANDARD   /* an output script is not a type a node will relay   */
} pc_result;

/* Four of these are nothing to do with the amount Bob is paid, and a merchant
 * refusing a customer over a fee a fraction of a koinu short, while saying the
 * payment pays less than it claims, is its own kind of broken. They are
 * separate so the reject can say which. */

const char *pc_strerror(pc_result r);

/* Amounts. The transaction overlay speaks decimal DOGE strings, the protocol
 * speaks koinu, and mixing the two is how you pay a hundred times too much. */
pc_result pc_doge_to_koinu(const char *doge, uint64_t *koinu_out);
void      pc_koinu_to_doge(uint64_t koinu, char *out, size_t cap);

/* ── Channel identity and state ──────────────────────────────── */

typedef struct {
    char     alice_pubkey_hex[PUBKEYHEXLEN];
    char     bob_pubkey_hex[PUBKEYHEXLEN];
    uint32_t locktime;                      /* refund becomes spendable here  */
    char     redeem_script_hex[PC_MAX_SCRIPT_HEX];
    char     p2sh_address[PC_ADDR_LEN];

    /* set once the funding transaction is known */
    char     funding_txid[DOGECOIN_HASH_HEX_LENGTH];
    int      funding_vout;
    uint64_t capacity_koinu;

    /* highest payment seen so far; a later one must pay Bob strictly more */
    uint64_t paid_to_bob_koinu;
    pc_chain chain;
} pc_channel;

/* Build the channel's redeem script and P2SH address from both pubkeys.
 *
 *   OP_IF <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <alice> OP_CHECKSIG
 *   OP_ELSE OP_2 <alice> <bob> OP_2 OP_CHECKMULTISIG OP_ENDIF
 *
 * Each branch is self contained. The IF branch gates Alice's unilateral refund
 * on the locktime and needs one signature; the ELSE branch is a plain 2-of-2.
 * Closing the ENDIF after the multisig rather than before it is what keeps them
 * apart: with a shared tail the refund would fall through into the multisig,
 * which the IF branch pushes no m for, and Alice's scriptSig would have to
 * carry the same signature twice and an m of its own to feed it. */
pc_result pc_channel_init(pc_channel *ch,
                          const char *alice_pubkey_hex,
                          const char *bob_pubkey_hex,
                          uint32_t locktime,
                          pc_chain chain);

/* Record the confirmed funding outpoint. Refuse to accept an unconfirmed one:
 * on a chain without SegWit the txid is malleable until it is buried. */
pc_result pc_channel_set_funding(pc_channel *ch,
                                 const char *txid_hex,
                                 int vout,
                                 uint64_t capacity_koinu);

/* ── Alice: build and sign a payment ─────────────────────────── */

/* Produce a PSBT spending the funding outpoint, paying (to_bob) to Bob's
 * address and the remainder back to Alice, signed with Alice's key. The
 * result is hex, caller frees with dogecoin_free(). */
pc_result pc_payment_create(const pc_channel *ch,
                            const char *funding_tx_hex,
                            const char *alice_wif,
                            const char *alice_addr,
                            const char *bob_addr,
                            uint64_t to_bob_koinu,
                            uint64_t fee_koinu,
                            char **psbt_hex_out);

/* ── Bob: verify, countersign, finalize ──────────────────────── */

/* Check a payment against the channel: it must spend the funding outpoint and
 * pay Bob strictly more than the previous one. Updates paid_to_bob on
 * acceptance. */
pc_result pc_payment_accept(pc_channel *ch,
                            const char *psbt_hex,
                            uint64_t claimed_to_bob_koinu);

/* Add Bob's signature and assemble the 2-of-2 scriptSig by hand, since the
 * redeem script's OP_IF branch means no built-in finalizer can classify it:
 *
 *   OP_0 <alice sig> <bob sig> OP_0 <redeem script>
 *
 * The trailing OP_0 selects the ELSE branch. Returns the broadcastable
 * transaction as hex; caller frees with dogecoin_free(). */
pc_result pc_payment_countersign(const pc_channel *ch,
                                 const char *psbt_hex,
                                 const char *bob_wif,
                                 char **raw_tx_hex_out);

/* ── Opening: Alice proposes a funding, Bob checks it ────────── */

/* Read a channel redeem script back into its parts, so Bob can learn who he is
 * dealing with from the script itself rather than being told out of band. Any
 * script that is not exactly the shape pc_channel_init() builds is refused. */
pc_result pc_redeem_parse(const char *redeem_hex, char alice_pubkey_hex[PUBKEYHEXLEN],
                          char bob_pubkey_hex[PUBKEYHEXLEN], uint32_t *locktime_out);

/* Find the output of (raw_tx_hex) that pays this channel, and what it is worth.
 * Bob is told a funding transaction, not an outpoint: which output funds the
 * channel is a fact about the transaction, so he works it out rather than
 * trusting it. */
pc_result pc_tx_find_channel_output(const pc_channel *ch, const char *raw_tx_hex,
                                    char txid_out[65], int *vout_out,
                                    uint64_t *value_out);

/* Alice: the opening PSBT. One input spending the funding output, no outputs
 * and no signatures, carrying the redeem script and the transaction that
 * created the input. Result is hex, caller frees with dogecoin_free(). */
pc_result pc_channel_open_create(const pc_channel *ch, const char *funding_tx_hex,
                                 char **psbt_hex_out);

/* Bob: accept or refuse an opening. The PSBT must spend the output of
 * (funding_tx_hex) that pays this channel, carry the redeem script Bob computed
 * from his own key and locktime, and carry no signatures yet. The locktime must
 * leave at least (min_slack) blocks above (chain_height), because a channel that
 * expires while Bob is holding a payment is one Alice can refund out from under
 * him. On success the channel is funded and (capacity_out) is what it is worth.
 *
 * The funding transaction travels beside the PSBT rather than inside it because
 * no published accessor reports a PSBT input's previous transaction, or its
 * outpoint at all. So this does not, and cannot, check that the PSBT spends the
 * output it derived: the PSBT is checked only for the redeem script and for
 * carrying no signatures and no outputs yet.
 *
 * What binds the channel to that outpoint is the payment rather than the
 * opening. pc_tx_verify_payment() requires the assembled transaction to spend
 * (funding_txid, funding_vout) exactly, so an opening that named a different
 * outpoint buys Alice nothing: she still has to produce a payment spending the
 * one Bob recorded. */
pc_result pc_channel_open_accept(pc_channel *ch, const char *psbt_hex,
                                 const char *funding_tx_hex,
                                 uint32_t chain_height, uint32_t min_slack,
                                 uint64_t *capacity_out);

/* ── Bob: verify what he is actually being paid ──────────────── */

/* Check the transaction Bob assembled before he treats it as money: exactly
 * one input, spending this channel's funding outpoint, paying at least
 * (claimed_to_bob_koinu) to the key in the redeem script, and spending no more
 * than the capacity.
 *
 * Bob's payee is derived from the channel rather than passed in, so a payment
 * only counts when it pays the key the channel was built around. Outputs are
 * matched as scripts, not addresses: base58 encoding has nothing to do with
 * whether the money arrives.
 *
 * This parses the raw transaction here rather than through libdogecoin because
 * dogecoin_tx is opaque in the published header and no PSBT accessor reports an
 * input's prevout or an output's value, so a receiving party cannot check what
 * it is being paid using the shipped surface alone. */
pc_result pc_tx_verify_payment(const pc_channel *ch,
                               const char *raw_tx_hex,
                               uint64_t claimed_to_bob_koinu);

/* MAX_MONEY from src/amount.h: 10,000,000,000 coins. Every value that crosses
 * this API is held to it, which is what makes the per-output bound in
 * pc_tx_verify_payment() mean something: the outputs sum inside a uint64, so
 * the total cannot wrap however the capacity was arrived at. */
#define PC_MAX_MONEY_KOINU 1000000000000000000ULL

/* How many outputs pc_tx_verify_payment() reads. The bound above only stops the
 * running total wrapping while this many of it still fit in a uint64, so that
 * relation is asserted rather than described: at 1e18 the ceiling is eighteen,
 * and raising this to nineteen fails the build instead of quietly making the
 * sum unsound. */
#define PC_MAX_OUTPUTS 16
_Static_assert(PC_MAX_OUTPUTS <= UINT64_MAX / PC_MAX_MONEY_KOINU,
               "PC_MAX_OUTPUTS outputs of PC_MAX_MONEY_KOINU would wrap");

/* Dogecoin's dust limits, from src/policy/policy.h. An output under the hard
 * limit makes the whole transaction non-standard; one under the soft limit adds
 * a full soft limit to the fee the transaction has to pay. */
#define PC_HARD_DUST_KOINU  100000ULL   /* DEFAULT_HARD_DUST_LIMIT */
#define PC_SOFT_DUST_KOINU 1000000ULL   /* DEFAULT_DUST_LIMIT      */

/* What a transaction of (txbytes) carrying (soft_dust_outputs) outputs under the
 * soft limit has to pay before a default-configured miner will include it. This
 * is the higher of the relay floor plus its dust surcharge and the block floor,
 * because clearing only the first gets a transaction that propagates and is
 * never mined. */
uint64_t pc_min_fee(size_t txbytes, size_t soft_dust_outputs);

/* Roughly what a payment on this channel serializes to: one input carrying two
 * signatures and the redeem script, and two p2pkh outputs. Alice cannot know
 * the real size before Bob countersigns, so this is what she sizes her fee
 * against to catch one that could never work. */
#define PC_TYPICAL_TX_BYTES 400

/* The legacy SIGHASH_ALL digest for the single input of (raw_tx_hex), with
 * (script_code) standing in where the scriptSig sits. Computed here because
 * dogecoin_tx_sighash() is LIBDOGECOIN_API but declared in tx.h, which is not
 * an installed header. */
pc_result pc_tx_sighash(const char *raw_tx_hex,
                        const unsigned char *script_code, size_t sclen,
                        unsigned char out[32]);

/* ── Alice: take the money back if Bob goes away ─────────────── */

/* Spend the funding output through the IF branch, paying everything but
 * (fee_koinu) to (alice_addr). The scriptSig is
 *
 *   <alice sig> OP_1 <redeem script>
 *
 * where OP_1 selects the refund branch. nLockTime is the channel's locktime and
 * the input is non-final, both of which CHECKLOCKTIMEVERIFY requires, so no
 * node will mine this until the locktime passes. Returns the transaction as
 * hex; caller frees with dogecoin_free().
 *
 * This is the only way Alice gets her money back, so it is the one branch worth
 * broadcasting on regtest before trusting it. */
pc_result pc_refund_create(const pc_channel *ch,
                           const char *alice_wif,
                           const char *alice_addr,
                           uint64_t fee_koinu,
                           char **raw_tx_hex_out);

/* ── Wire envelope ───────────────────────────────────────────── */

/* One line of JSON per message, following the flow in doc/PROTOCOL.md.
 *
 *   request   Alice asks for a channel. no payload
 *   announce  Bob returns the pubkey he will sign this channel with
 *   open      Alice's funding PSBT: the funding input, its redeem script and
 *             the transaction that created it, no outputs and no signatures.
 *             (tx) carries that funding transaction, which Bob cannot read back
 *             out of the PSBT through the published accessors. to_bob is the
 *             locktime, ref the funding txid, vout its index
 *   accept    Bob has checked the funding and will take payments on it.
 *             to_bob is the capacity he read from it
 *   reject    Bob will not. (addr) carries the reason
 *   invoice   Bob asks for a total. to_bob is the cumulative amount now owed,
 *             (addr) where he wants it
 *   payment   Alice's PSBT paying that total, signed by her
 *   ack       Bob has verified and stored it. to_bob echoes the total held,
 *             (more) says whether an invoice follows. Bob is the only one who
 *             knows the order is finished, so without it Alice waits for an
 *             invoice that never comes and both sides block in recv
 *   close     from Alice "01" and means close now; from Bob the final raw
 *             transaction
 */
typedef enum {
    PC_MSG_REQUEST,
    PC_MSG_ANNOUNCE,
    PC_MSG_OPEN,
    PC_MSG_ACCEPT,
    PC_MSG_REJECT,
    PC_MSG_INVOICE,
    PC_MSG_PAYMENT,
    PC_MSG_ACK,
    PC_MSG_CLOSE
} pc_msg_type;

typedef struct {
    pc_msg_type type;
    char        ref[65];                 /* channel reference, the funding txid */
    int         vout;                    /* which output of it funds the channel */
    int         more;                    /* on an ack, another invoice follows */
    uint64_t    to_bob_koinu;
    char        addr[P2PKHLEN];          /* an address, or a short reason */
    char        psbt_hex[PC_MAX_PSBT_HEX];
    char        tx_hex[PC_MAX_PSBT_HEX];
} pc_envelope;

/* {"type":"payment","ref":"<hex>","vout":<n>,"more":<0|1>,"to_bob":<n>,"addr":"<b58>","psbt":"<hex>","tx":"<hex>"} */
pc_result pc_envelope_encode(const pc_envelope *env, char *out, size_t cap);
pc_result pc_envelope_decode(const char *json, pc_envelope *env);

#ifdef __cplusplus
}
#endif

#endif /* PAYMENT_CHANNEL_H */
