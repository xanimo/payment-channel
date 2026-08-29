/* Drives the protocol end to end without a node: build the channel, fund it
 * from a transaction we construct ourselves, have Alice pay twice, have Bob
 * accept and countersign, and check the result is a broadcastable transaction.
 *
 * No regtest here on purpose. This pins the parts that are ours: the redeem
 * script, the address it pays to, the PSBT exchange, the balance rule and the
 * hand-assembled scriptSig. contrib/regtest.sh drives the same flow against a
 * real node, which is what proves the transaction is actually accepted. */

#include "channel.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, ...) do {                                   \
    checks++;                                                   \
    if (!(cond)) {                                              \
        failures++;                                             \
        fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);    \
        fprintf(stderr, __VA_ARGS__);                           \
        fprintf(stderr, "\n");                                  \
    }                                                           \
} while (0)

#define CHECK_OK(rc, what) do {                                 \
    pc_result _r = (rc);                                        \
    checks++;                                                   \
    if (_r != PC_OK) {                                          \
        failures++;                                             \
        fprintf(stderr, "FAIL %s:%d: %s: %s\n",                 \
                __FILE__, __LINE__, what, pc_strerror(_r));     \
    }                                                           \
} while (0)

/* A funding transaction paying the channel's P2SH address. Built through the
 * overlay so the test uses only the public surface, same as the library does. */
static char *make_funding_tx(const char *p2sh_addr, const char *change_addr,
                             const char *doge_amount, const char *total,
                             char *txid_out)
{
    int tix = start_transaction();
    if (tix < 0) return NULL;
    /* any prevout will do: nothing verifies it in this test */
    if (!add_utxo(tix,
        (char *)"b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074", 0))
        return NULL;
    if (!add_output(tix, (char *)p2sh_addr, (char *)doge_amount)) return NULL;
    const char *tmp = finalize_transaction(tix, (char *)p2sh_addr, (char *)"1.0",
                                           (char *)total, (char *)change_addr);
    if (!tmp) return NULL;
    char *hex = strdup(tmp);   /* static buffer, copy before the next hex call */
    if (!hex) return NULL;

    /* the txid, in display order */
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

int main(void)
{
    dogecoin_ecc_start();

    /* ── two parties ─────────────────────────────────────────── */
    char alice_wif[PRIVKEYWIFLEN], alice_addr[P2PKHLEN];
    char bob_wif[PRIVKEYWIFLEN],   bob_addr[P2PKHLEN];
    CHECK(generatePrivPubKeypair(alice_wif, alice_addr, false), "alice keygen");
    CHECK(generatePrivPubKeypair(bob_wif,   bob_addr,   false), "bob keygen");

    char alice_pub[PUBKEYHEXLEN], bob_pub[PUBKEYHEXLEN];
    size_t na = sizeof(alice_pub), nb = sizeof(bob_pub);
    CHECK(getPubkeyFromPrivkey(alice_wif, false, alice_pub, &na), "alice pubkey");
    CHECK(getPubkeyFromPrivkey(bob_wif,   false, bob_pub,   &nb), "bob pubkey");

    /* ── the channel ─────────────────────────────────────────── */
    pc_channel ch;
    CHECK_OK(pc_channel_init(&ch, alice_pub, bob_pub, 300000, 0), "channel_init");
    printf("  redeem script : %.48s...\n", ch.redeem_script_hex);
    printf("  P2SH address  : %s\n", ch.p2sh_address);
    CHECK(ch.p2sh_address[0] == 'A' || ch.p2sh_address[0] == '9',
          "mainnet P2SH prefix, got %c", ch.p2sh_address[0]);

    /* the script must round-trip to the same address independently */
    char again[P2SHLEN];
    CHECK(get_p2sh_address_from_script(ch.redeem_script_hex, 0, again, sizeof(again)),
          "address from script");
    CHECK(strcmp(again, ch.p2sh_address) == 0, "address is deterministic");

    /* a different locktime must give a different channel */
    pc_channel other;
    CHECK_OK(pc_channel_init(&other, alice_pub, bob_pub, 300001, 0), "other init");
    CHECK(strcmp(other.p2sh_address, ch.p2sh_address) != 0,
          "locktime is committed to by the address");

    /* rejections */
    CHECK(pc_channel_init(&ch, alice_pub, bob_pub, 0, 0) == PC_ERR_ARG, "zero locktime");
    CHECK(pc_channel_init(&ch, "deadbeef", bob_pub, 300000, 0) == PC_ERR_ARG, "short pubkey");
    CHECK(pc_channel_init(&ch, alice_pub, bob_pub, 500000001u, 0) == PC_ERR_ARG,
          "timestamp locktimes are refused");
    CHECK_OK(pc_channel_init(&ch, alice_pub, bob_pub, 300000, 0), "re-init");

    /* ── fund it ─────────────────────────────────────────────── */
    char funding_txid[65] = {0};
    char *funding_hex = make_funding_tx(ch.p2sh_address, alice_addr,
                                        "100.0", "150.0", funding_txid);
    CHECK(funding_hex != NULL, "funding tx built");
    if (!funding_hex) goto done;
    printf("  funding txid  : %s\n", funding_txid);

    CHECK(pc_payment_create(&ch, funding_hex, alice_wif, alice_addr, bob_addr,
                            100000000, 100000000, NULL) == PC_ERR_ARG,
          "null out is refused");
    CHECK_OK(pc_channel_set_funding(&ch, funding_txid, 0, 10000000000ULL),
             "set_funding");

    /* ── first payment: 10 DOGE to Bob ───────────────────────── */
    char *psbt1 = NULL;
    CHECK_OK(pc_payment_create(&ch, funding_hex, alice_wif, alice_addr, bob_addr,
                               1000000000ULL, 100000000ULL, &psbt1),
             "payment 1 create");
    CHECK(psbt1 != NULL, "payment 1 produced a psbt");
    if (psbt1) printf("  payment 1     : %.40s...\n", psbt1);

    if (psbt1) {
        CHECK_OK(pc_payment_accept(&ch, psbt1, 1000000000ULL), "payment 1 accept");
        CHECK(ch.paid_to_bob_koinu == 1000000000ULL, "balance advanced");

        /* a replay of the same amount must be refused */
        CHECK(pc_payment_accept(&ch, psbt1, 1000000000ULL) == PC_ERR_AMOUNT,
              "replay refused");
        /* and so must a smaller one */
        CHECK(pc_payment_accept(&ch, psbt1, 500000000ULL) == PC_ERR_AMOUNT,
              "backwards payment refused");
    }

    /* ── second payment: 20 DOGE, and close on it ────────────── */
    char *psbt2 = NULL;
    CHECK_OK(pc_payment_create(&ch, funding_hex, alice_wif, alice_addr, bob_addr,
                               2000000000ULL, 100000000ULL, &psbt2),
             "payment 2 create");
    if (psbt2) {
        CHECK_OK(pc_payment_accept(&ch, psbt2, 2000000000ULL), "payment 2 accept");
        CHECK(ch.paid_to_bob_koinu == 2000000000ULL, "balance advanced again");

        char *raw = NULL;
        CHECK_OK(pc_payment_countersign(&ch, psbt2, bob_wif, &raw), "countersign");
        CHECK(raw != NULL, "countersign produced a transaction");
        if (raw) {
            size_t rl = strlen(raw);
            printf("  closing tx    : %.40s... (%zu hex chars)\n", raw, rl);
            CHECK(rl > 0 && rl % 2 == 0, "closing tx is whole bytes");
            /* the redeem script must appear in the scriptSig we assembled */
            CHECK(strstr(raw, ch.redeem_script_hex) != NULL,
                  "redeem script is present in the final scriptSig");

            /* what Bob checks before he calls it money */
            CHECK_OK(pc_tx_verify_payment(&ch, raw, 2000000000ULL),
                     "closing tx pays what was claimed");
            CHECK(pc_tx_verify_payment(&ch, raw, 2000000001ULL) == PC_ERR_AMOUNT,
                  "claiming one koinu more is refused");
            {   /* the same transaction read as a channel with a different payee */
                char carol_wif[PRIVKEYWIFLEN], carol_addr[P2PKHLEN];
                char carol_pub[PUBKEYHEXLEN];
                size_t cn = sizeof(carol_pub);
                generatePrivPubKeypair(carol_wif, carol_addr, false);
                getPubkeyFromPrivkey(carol_wif, false, carol_pub, &cn);
                pc_channel other_payee = ch;
                snprintf(other_payee.bob_pubkey_hex,
                         sizeof(other_payee.bob_pubkey_hex), "%s", carol_pub);
                CHECK(pc_tx_verify_payment(&other_payee, raw, 1) == PC_ERR_AMOUNT,
                      "a payment to another key counts for nothing");
            }
            {   /* the same transaction against a different funding outpoint */
                pc_channel wrong = ch;
                wrong.funding_vout = 7;
                CHECK(pc_tx_verify_payment(&wrong, raw, 1) != PC_OK,
                      "wrong outpoint is refused");
                wrong = ch;
                memset(wrong.funding_txid, '0', 64);
                CHECK(pc_tx_verify_payment(&wrong, raw, 1) != PC_OK,
                      "wrong funding txid is refused");
            }
            CHECK(pc_tx_verify_payment(&ch, "00", 1) != PC_OK,
                  "garbage is refused");
            {   /* trailing bytes must not be ignored */
                size_t n = strlen(raw);
                char *extra = malloc(n + 3);
                memcpy(extra, raw, n);
                memcpy(extra + n, "00", 3);
                CHECK(pc_tx_verify_payment(&ch, extra, 1) != PC_OK,
                      "trailing bytes are refused");
                free(extra);
            }
            dogecoin_free(raw);
        }

        /* Bob alone cannot countersign a payment Alice never signed */
        char *nope = NULL;
        pc_channel empty;
        pc_channel_init(&empty, alice_pub, bob_pub, 300000, 0);
        CHECK(pc_payment_countersign(&empty, "not hex", bob_wif, &nope) != PC_OK,
              "garbage psbt refused");
        dogecoin_free(psbt2);
    }
    if (psbt1) dogecoin_free(psbt1);
    free(funding_hex);

    /* ── amounts ─────────────────────────────────────────────── */
    uint64_t k = 0;
    CHECK_OK(pc_doge_to_koinu("1.0", &k), "1.0 parses");
    CHECK(k == 100000000ULL, "1.0 is 1e8 koinu, got %" PRIu64, k);
    CHECK_OK(pc_doge_to_koinu("0.00000001", &k), "one koinu parses");
    CHECK(k == 1, "smallest unit");
    CHECK_OK(pc_doge_to_koinu("100", &k), "whole numbers parse");
    CHECK(k == 10000000000ULL, "100 DOGE");
    CHECK(pc_doge_to_koinu("1.000000001", &k) == PC_ERR_ARG, "finer than koinu refused");
    CHECK(pc_doge_to_koinu("", &k) == PC_ERR_ARG, "empty refused");
    CHECK(pc_doge_to_koinu("1.2.3", &k) == PC_ERR_ARG, "two points refused");
    CHECK(pc_doge_to_koinu("-1", &k) == PC_ERR_ARG, "negative refused");
    CHECK(pc_doge_to_koinu("99999999999999999999", &k) == PC_ERR_ARG, "overflow refused");
    {   /* round trip */
        char buf[32];
        pc_koinu_to_doge(123456789ULL, buf, sizeof(buf));
        uint64_t back = 0;
        CHECK_OK(pc_doge_to_koinu(buf, &back), "round trip parses");
        CHECK(back == 123456789ULL, "round trip is exact");
    }

    /* ── envelope ────────────────────────────────────────────── */
    pc_envelope env, back;
    memset(&env, 0, sizeof(env));
    env.type = PC_MSG_PAYMENT;
    snprintf(env.ref, sizeof(env.ref), "%s", funding_txid);
    env.to_bob_koinu = 2000000000ULL;
    snprintf(env.psbt_hex, sizeof(env.psbt_hex), "70736274ff01");
    char wire[512];
    CHECK_OK(pc_envelope_encode(&env, wire, sizeof(wire)), "envelope encode");
    printf("  envelope      : %s\n", wire);
    CHECK_OK(pc_envelope_decode(wire, &back), "envelope decode");
    CHECK(back.type == PC_MSG_PAYMENT, "type round-trips");
    CHECK(strcmp(back.ref, env.ref) == 0, "ref round-trips");
    CHECK(back.to_bob_koinu == env.to_bob_koinu, "amount round-trips");
    CHECK(strcmp(back.psbt_hex, env.psbt_hex) == 0, "psbt round-trips");

    CHECK(pc_envelope_decode("{\"type\":\"nope\",\"psbt\":\"00\"}", &back) != PC_OK,
          "unknown type refused");
    CHECK(pc_envelope_decode("{\"type\":\"payment\",\"psbt\":\"zz\"}", &back) != PC_OK,
          "non-hex psbt refused");
    CHECK(pc_envelope_decode("{\"type\":\"payment\"}", &back) != PC_OK,
          "missing psbt refused");
    CHECK(pc_envelope_decode("{\"type\":\"payment\",\"ref\":\"abc\",\"psbt\":\"00\"}",
                             &back) != PC_OK, "short ref refused");

done:
    dogecoin_ecc_stop();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
