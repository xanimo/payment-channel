/* What a payment costs off chain, measured, with the parts it does not measure
 * named so the number cannot be quoted out of what it covers.
 *
 * A payment never touches the chain. Per payment Alice signs a PSBT, Bob
 * countersigns (which is how he verifies both signatures), verifies the
 * assembled transaction, ratchets, and persists it durably before he acks. The
 * ratchet compare is nanoseconds; the durable write is an fsync, and that, not
 * the compare, is the floor a merchant feels. Both are timed here.
 *
 * What this does NOT measure, and what the headline therefore excludes: the
 * socket round trip and its 30s line budget, the per-connection fork, the ecc
 * context setup (one-time, not per payment), and fsync under concurrent load on
 * a contended disk. Those live in the real bob and in contrib/regtest.sh, not
 * here. The scale block at the end states the session model rather than
 * measuring it, since it is a fixed cap, not a curve. */

#include "channel.h"
#include "hex.h"
#include "state.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

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

    /* Bob: persist the ratchet durably before acking. This is tmp write, fsync,
       rename, then an fsync of the directory, so the ack is never sent against a
       payment a crash would forget. It is the one disk-bound step per payment
       and the floor a merchant actually feels. */
    char dir[] = "/tmp/pcbenchXXXXXX";
    double d_persist = -1.0;
    long state_bytes = 0;
    long persist_iters = iters < 2000 ? iters : 2000;   /* fsync is ~1e3x slower */
    if (mkdtemp(dir)) {
        pc_state stt;
        if (pc_state_open(&stt, dir, &ch) == PC_OK) {
            t = now_s();
            for (long i = 0; i < persist_iters; i++) {
                if (pc_state_save(&stt, &ch, raw0) != PC_OK) {
                    fprintf(stderr, "persist failed\n"); return 1;
                }
            }
            d_persist = now_s() - t;
            pc_state_close(&stt);
        }
        char p[300];
        snprintf(p, sizeof(p), "%s/%s-0.channel", dir, txid);
        struct stat sb;
        if (stat(p, &sb) == 0) state_bytes = (long)sb.st_size;
        /* leave no state behind */
        unlink(p);
        snprintf(p, sizeof(p), "%s/%s-0.channel.lock", dir, txid); unlink(p);
        snprintf(p, sizeof(p), "%s/%s-0.channel.tmp", dir, txid); unlink(p);
        rmdir(dir);
    }
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
    if (d_persist > 0) report("state_save fsync (bob)",   d_persist, persist_iters);

    /* Per payment: Alice signs once (create); Bob countersigns, verifies,
       ratchets, and persists durably before acking. The two sides run on
       different hosts, so pipelined throughput is bounded by the slower one. */
    double alice   = d_create / (double)iters;
    double persist = d_persist > 0 ? d_persist / (double)persist_iters : 0.0;
    double bob     = (d_close + d_verify + d_accept) / (double)iters + persist;
    double slower  = alice > bob ? alice : bob;
    printf("\nper payment: alice %.0f us (create), bob %.0f us "
           "(countersign+verify+accept + %.0f us fsync)\n",
           alice * 1e6, bob * 1e6, persist * 1e6);
    printf("throughput: %.0f payments/s per channel pipelined across the two "
           "hosts, %.0f/s if both share one core\n",
           1.0 / slower, 1.0 / (alice + bob));
    if (persist > 0)
        printf("            the fsync is %.0f%% of bob's cost and sets the "
               "per-channel ceiling; it is disk-bound, not CPU-bound\n",
               100.0 * persist / bob);

    /* Scale is a session cap, not a curve, so it is stated not measured. Bob is
       fork-per-connection capped at MAX_CONNS concurrent sessions (64 by
       default, 16 per source ip); the next connection is refused, not queued or
       degraded. A channel at rest is one ~%zu-byte state file: no process, no
       memory, no fd, so channels held between sessions are bounded by disk, not
       by bob. A thousand idle channels cost a thousand small files; a thousand
       simultaneous opens serve 64 and reject the rest. */
    printf("\nscale: <= MAX_CONNS concurrent sessions (fork per connection), "
           "channels at rest are ~%zu-byte files bounded by disk not memory\n",
           (size_t)state_bytes);
    printf("not measured here: socket round trip, the fork, ecc setup, fsync "
           "under concurrent-disk contention\n");
    return 0;
}
