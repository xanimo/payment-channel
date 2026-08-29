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
    int      is_testnet;
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
                          int is_testnet);

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

/* ── Bob: verify what he is actually being paid ──────────────── */

/* Check the transaction Bob assembled before he treats it as money: exactly
 * one input, spending this channel's funding outpoint, paying (bob_addr) at
 * least (claimed_to_bob_koinu), and spending no more than the capacity.
 *
 * This parses the raw transaction here rather than through libdogecoin because
 * dogecoin_tx is opaque in the published header and no PSBT accessor reports an
 * input's prevout or an output's value, so a receiving party cannot check what
 * it is being paid using the shipped surface alone. */
pc_result pc_tx_verify_payment(const pc_channel *ch,
                               const char *raw_tx_hex,
                               const char *bob_addr,
                               uint64_t claimed_to_bob_koinu);

/* ── Wire envelope ───────────────────────────────────────────── */

/* One line of JSON per message. The (psbt) field is a hex payload whose
 * meaning follows the type:
 *
 *   announce  the sender's compressed pubkey; to_bob carries the locktime
 *   payment   the PSBT; ref is the funding txid, to_bob the cumulative total
 *   ack       "01"; to_bob echoes the total the receiver now considers paid
 *   close     the final raw transaction; to_bob the total it pays
 */
typedef enum {
    PC_MSG_ANNOUNCE,
    PC_MSG_PAYMENT,
    PC_MSG_ACK,
    PC_MSG_CLOSE
} pc_msg_type;

typedef struct {
    pc_msg_type type;
    char        ref[65];                 /* channel reference, the funding txid */
    uint64_t    to_bob_koinu;
    char        psbt_hex[PC_MAX_PSBT_HEX];
} pc_envelope;

/* {"type":"payment","ref":"<hex>","to_bob":<n>,"psbt":"<hex>"} */
pc_result pc_envelope_encode(const pc_envelope *env, char *out, size_t cap);
pc_result pc_envelope_decode(const char *json, pc_envelope *env);

#ifdef __cplusplus
}
#endif

#endif /* PAYMENT_CHANNEL_H */
