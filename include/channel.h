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

#define PC_MAX_SCRIPT_HEX   1024   /* 520-byte redeem script as hex, plus NUL */
#define PC_MAX_PSBT_HEX    16384
#define PC_ADDR_LEN        P2SHLEN

typedef enum {
    PC_OK = 0,
    PC_ERR_ARG,          /* a caller argument was missing or malformed        */
    PC_ERR_KEY,          /* a WIF key would not decode                        */
    PC_ERR_SCRIPT,       /* the redeem script would not build or hash         */
    PC_ERR_PSBT,         /* a PSBT would not parse, sign, or finalize         */
    PC_ERR_STATE,        /* the channel is not in a state that allows this    */
    PC_ERR_AMOUNT        /* the payment does not respect the channel balance  */
} pc_result;

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
 *   OP_IF <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <alice> OP_CHECKSIGVERIFY
 *   OP_ELSE OP_2 OP_ENDIF <alice> <bob> OP_2 OP_CHECKMULTISIG
 *
 * The ELSE branch pushes OP_2 so the cooperative close is a plain 2-of-2. The
 * IF branch gates Alice's unilateral refund on the locktime. */
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
 * Bob cannot read the funding transaction back out of the PSBT: no published
 * accessor reports an input's previous transaction, so it travels beside it and
 * is checked against the outpoint the PSBT actually spends. */
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
