/* Off-chain cost of the channel: how fast the parts that run per payment go.
 *
 * A payment never touches the chain, so its cost is CPU: Alice signs a PSBT,
 * Bob parses and verifies it, and at close Bob countersigns once. This times
 * each in isolation and the steady-state pair (create + accept) that bounds
 * payments per second, plus the envelope round trip the wire pays each message.
 *
 * Not a network benchmark: no sockets, no fork, no libdogecoin ecc setup cost.
 * contrib/regtest.sh is where on-chain latency lives. */

#include "channel.h"
#include "hex.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void report(const char *name, double secs, long iters)
{
    double per = secs / (double)iters;
    printf("  %-28s %9.2f k ops/s   %8.2f us/op\n",
           name, (double)iters / secs / 1000.0, per * 1e6);
}

/* Mint a funding transaction paying the channel's P2SH. Nothing verifies the
   prevout here, the same as the protocol tests. */
static char *make_funding_tx(const char *p2sh_addr, const char *change_addr,
                             char *txid_out)
{
    int tix = start_transaction();
    if (tix < 0) return NULL;
    if (!add_utxo(tix,
        (char *)"b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074", 0))
        return NULL;
    if (!add_output(tix, (char *)p2sh_addr, (char *)"100.0")) return NULL;
    char *hex = (char *)malloc(DOGECOIN_MAX_TX_HEX_LEN);
    if (!hex) return NULL;
    if (!finalize_transaction_ex(tix, (char *)p2sh_addr, (char *)"1.0",
                                 (char *)"150.0", (char *)change_addr,
                                 hex, DOGECOIN_MAX_TX_HEX_LEN)) {
        free(hex); return NULL;
    }
    size_t hl = strlen(hex), blen = 0;
    unsigned char *b = malloc(hl / 2 + 1);
    utils_hex_to_bin(hex, b, hl, &blen);
    dogecoin_tx *tx = dogecoin_tx_new();
    dogecoin_tx_deserialize(b, blen, tx, NULL);
    free(b);
    uint256_t txid;
    dogecoin_tx_hash(tx, txid);
    unsigned char rev[32];
    for (int i = 0; i < 32; i++) rev[i] = txid[31 - i];
    utils_bin_to_hex(rev, 32, txid_out);
    dogecoin_tx_free(tx);
    remove_all();
    return hex;
}

int main(int argc, char **argv)
{
    long iters = (argc > 1) ? strtol(argv[1], NULL, 10) : 20000;
    if (iters < 1) iters = 1;

    dogecoin_ecc_start();

    char alice_wif[PRIVKEYWIFLEN], alice_addr[P2PKHLEN];
    char bob_wif[PRIVKEYWIFLEN],   bob_addr[P2PKHLEN];
    if (!generatePrivPubKeypair(alice_wif, alice_addr, false) ||
        !generatePrivPubKeypair(bob_wif, bob_addr, false)) {
        fprintf(stderr, "keygen failed\n"); return 1;
    }
    char alice_pub[PUBKEYHEXLEN], bob_pub[PUBKEYHEXLEN];
    size_t na = sizeof(alice_pub), nb = sizeof(bob_pub);
    getPubkeyFromPrivkey(alice_wif, false, alice_pub, &na);
    getPubkeyFromPrivkey(bob_wif,   false, bob_pub,   &nb);

    char txid[65] = {0};

    /* channel setup: redeem-script build + both pubkeys validated as points */
    double t = now_s();
    pc_channel ch;
    for (long i = 0; i < iters; i++) {
        if (pc_channel_init(&ch, alice_pub, bob_pub, 300000, PC_CHAIN_MAIN) != PC_OK) {
            fprintf(stderr, "init failed\n"); return 1;
        }
    }
    double d_init = now_s() - t;

    char *funding = make_funding_tx(ch.p2sh_address, alice_addr, txid);
    if (!funding) { fprintf(stderr, "funding failed\n"); return 1; }
    if (pc_channel_set_funding(&ch, txid, 0, 10000000000ULL) != PC_OK) {
        fprintf(stderr, "set_funding failed\n"); return 1;
    }

    /* one payment of 10 DOGE, reused where a phase needs a valid input */
    const uint64_t to_bob = 1000000000ULL, fee = 100000000ULL;
    char *psbt0 = NULL;
    if (pc_payment_create(&ch, funding, alice_wif, alice_addr, bob_addr,
                          to_bob, fee, &psbt0) != PC_OK || !psbt0) {
        fprintf(stderr, "warmup create failed\n"); return 1;
    }

    /* Alice: build and sign a payment PSBT */
    t = now_s();
    for (long i = 0; i < iters; i++) {
        char *p = NULL;
        if (pc_payment_create(&ch, funding, alice_wif, alice_addr, bob_addr,
                              to_bob, fee, &p) != PC_OK) {
            fprintf(stderr, "create failed\n"); return 1;
        }
        dogecoin_free(p);
    }
    double d_create = now_s() - t;

    /* Bob: parse the PSBT and verify both signatures. Reset the ratchet each
       time so the same payment re-accepts rather than being refused as a replay;
       that isolates the parse+verify cost, which is what a payment costs Bob. */
    t = now_s();
    for (long i = 0; i < iters; i++) {
        ch.paid_to_bob_koinu = 0;
        if (pc_payment_accept(&ch, psbt0, to_bob) != PC_OK) {
            fprintf(stderr, "accept failed\n"); return 1;
        }
    }
    double d_accept = now_s() - t;
    ch.paid_to_bob_koinu = 0;

    /* Bob: countersign and assemble the final scriptSig. This is not a
       close-only cost: handle_payment countersigns every payment, because
       assembling the transaction is how Bob verifies both signatures and reads
       the real outpoint and amounts before he acks. */
    t = now_s();
    for (long i = 0; i < iters; i++) {
        char *raw = NULL;
        if (pc_payment_countersign(&ch, psbt0, bob_wif, &raw) != PC_OK) {
            fprintf(stderr, "countersign failed\n"); return 1;
        }
        dogecoin_free(raw);
    }
    double d_close = now_s() - t;

    /* Bob: check the assembled transaction spends the funding outpoint and pays
       what it claims. Runs on every payment right after the countersign. */
    char *raw0 = NULL;
    if (pc_payment_countersign(&ch, psbt0, bob_wif, &raw0) != PC_OK || !raw0) {
        fprintf(stderr, "warmup countersign failed\n"); return 1;
    }
    t = now_s();
    for (long i = 0; i < iters; i++) {
        if (pc_tx_verify_payment(&ch, raw0, to_bob) != PC_OK) {
            fprintf(stderr, "verify_payment failed\n"); return 1;
        }
    }
    double d_verify = now_s() - t;
    dogecoin_free(raw0);

    /* wire: encode an envelope and parse it back */
    pc_envelope env, back;
    memset(&env, 0, sizeof(env));
    env.type = PC_MSG_PAYMENT;
    env.vout = 0;
    env.to_bob_koinu = to_bob;
    snprintf(env.ref, sizeof(env.ref), "%s", txid);
    snprintf(env.psbt_hex, sizeof(env.psbt_hex), "%s", psbt0);
    char line[2 * PC_MAX_PSBT_HEX + 512];
    t = now_s();
    for (long i = 0; i < iters; i++) {
        if (pc_envelope_encode(&env, line, sizeof(line)) != PC_OK ||
            pc_envelope_decode(line, &back) != PC_OK) {
            fprintf(stderr, "envelope failed\n"); return 1;
        }
    }
    double d_env = now_s() - t;

    dogecoin_free(psbt0);
    free(funding);
    dogecoin_ecc_stop();

    printf("payment-channel off-chain cost (%ld iterations each)\n", iters);
    report("channel_init (open)",         d_init,   iters);
    report("payment_create (alice)",      d_create, iters);
    report("payment_countersign (bob)",   d_close,  iters);
    report("verify_payment (bob)",        d_verify, iters);
    report("payment_accept (bob)",        d_accept, iters);
    report("envelope encode+decode",      d_env,    iters);

    /* Per payment, Alice signs once (create); Bob countersigns, verifies the
       assembled tx, and ratchets, all before he acks. The two sides run on
       different hosts, so pipelined throughput is bounded by the slower one. */
    double alice = d_create / (double)iters;
    double bob   = (d_close + d_verify + d_accept) / (double)iters;
    double slower = alice > bob ? alice : bob;
    printf("\nper payment: alice %.0f us (create), bob %.0f us "
           "(countersign+verify+accept)\n", alice * 1e6, bob * 1e6);
    printf("throughput: %.0f payments/s pipelined across the two hosts, "
           "%.0f/s if both share one core\n",
           1.0 / slower, 1.0 / (alice + bob));
    return 0;
}
