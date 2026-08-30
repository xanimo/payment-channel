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

/* the library's decoder is static, and the test only needs this once */
static int hex_bytes(const char *hex, unsigned char **out, size_t *outlen)
{
    size_t n = strlen(hex);
    if (n == 0 || (n % 2)) return 0;
    unsigned char *b = (unsigned char *)malloc(n / 2 + 1);
    if (!b) return 0;
    size_t got = 0;
    utils_hex_to_bin(hex, b, n, &got);
    if (got != n / 2) { free(b); return 0; }
    *out = b; *outlen = got;
    return 1;
}

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
    char *hex = (char *)malloc(DOGECOIN_MAX_TX_HEX_LEN);
    if (!hex) return NULL;
    if (!finalize_transaction_ex(tix, (char *)p2sh_addr, (char *)"1.0",
                                 (char *)total, (char *)change_addr,
                                 hex, DOGECOIN_MAX_TX_HEX_LEN)) {
        free(hex);
        return NULL;
    }

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

            /* Being addressed correctly is not the same as being spendable.
               Everything above checks who is paid and how much; these check
               that what Bob holds would survive a node. */
            {
                /* The layout being dissected, asserted first so a change here
                   fails loudly rather than skipping the checks below. Offsets
                   are in hex characters from the start of the transaction:

                       0   version          4 bytes
                       8   input count      1
                       10  prevout txid     32
                       74  prevout vout     4
                       82  scriptSig len    varint, 0xfd + 2 for our length
                       88  OP_0             the CHECKMULTISIG dummy
                       90  push length      1
                       92  alice's sig      DER, starts 0x30

                   a serialization change shifts all of them together, so read
                   the first failure here rather than the five that follow. */
                CHECK(rl > 200, "transaction long enough to dissect");
                CHECK(memcmp(raw + 82, "fd", 2) == 0, "scriptSig has a 2-byte varint");
                CHECK(memcmp(raw + 88, "00", 2) == 0, "scriptSig opens with OP_0");
                CHECK(memcmp(raw + 92, "30", 2) == 0, "alice's signature is DER");

                char lo[3] = { raw[84], raw[85], 0 };
                char hi[3] = { raw[86], raw[87], 0 };
                size_t sslen = (size_t)strtoul(hi, NULL, 16) * 256 +
                               (size_t)strtoul(lo, NULL, 16);
                size_t seq_off = 88 + sslen * 2;
                CHECK(memcmp(raw + seq_off, "ffffffff", 8) == 0,
                      "the input is final as built");

                /* any DER-shaped blob keyed to alice would otherwise pass */
                char *bad = strdup(raw);
                bad[101] = (bad[101] == 'a') ? 'b' : 'a';
                CHECK(pc_tx_verify_payment(&ch, bad, 2000000000ULL) != PC_OK,
                      "a corrupted alice signature is refused");
                free(bad);

                /* nothing in the ELSE branch executes CLTV, so the script does
                   not constrain either field and Bob has to */
                char *lt = strdup(raw);
                memcpy(lt + rl - 8, "40420f00", 8);
                CHECK(pc_tx_verify_payment(&ch, lt, 2000000000ULL) == PC_ERR_FINAL,
                      "a future locktime is refused");
                free(lt);

                char *sq = strdup(raw);
                memcpy(sq + seq_off, "feffffff", 8);
                CHECK(pc_tx_verify_payment(&ch, sq, 2000000000ULL) == PC_ERR_FINAL,
                      "a non-final sequence is refused");
                free(sq);
            }
            {   /* what is left over is the fee, and a miner has a floor that
                   is ten times the one a relay has. computed here from the
                   constants rather than from pc_min_fee(), so the test does not
                   check the code against itself. */
                const uint64_t OUTPUTS = 9900000000ULL;
                uint64_t bytes = (uint64_t)(rl / 2);
                uint64_t relay_floor = 100000ULL  * bytes / 1000;
                uint64_t block_floor = 1000000ULL * bytes / 1000;

                pc_channel zero = ch;
                zero.capacity_koinu = OUTPUTS;         /* what the outputs spend */
                CHECK(pc_tx_verify_payment(&zero, raw, 2000000000ULL) == PC_ERR_FEE,
                      "a zero-fee payment is refused");

                /* the one that matters: a fee that relays and never gets mined */
                pc_channel relayonly = ch;
                relayonly.capacity_koinu = OUTPUTS + relay_floor;
                CHECK(pc_tx_verify_payment(&relayonly, raw, 2000000000ULL) == PC_ERR_FEE,
                      "the relay floor alone is refused");

                pc_channel under = ch;
                under.capacity_koinu = OUTPUTS + block_floor - 1;
                CHECK(pc_tx_verify_payment(&under, raw, 2000000000ULL) == PC_ERR_FEE,
                      "one koinu under the block floor is refused");

                pc_channel atfloor = ch;
                atfloor.capacity_koinu = OUTPUTS + block_floor;
                CHECK_OK(pc_tx_verify_payment(&atfloor, raw, 2000000000ULL),
                         "the block floor exactly is accepted");
            }
            {   /* one dusty output makes the whole transaction non-standard, so
                   the newest state would be worthless and bob would have to
                   fall back to an older one. patch the change output's value,
                   which the amount checks read before any signature check. */
                char *dusty = strdup(raw);
                char lo[3] = { raw[84], raw[85], 0 };
                char hi[3] = { raw[86], raw[87], 0 };
                size_t sslen = (size_t)strtoul(hi, NULL, 16) * 256 +
                               (size_t)strtoul(lo, NULL, 16);
                size_t nout_off = 88 + sslen * 2 + 8;      /* past the sequence */
                CHECK(memcmp(dusty + nout_off, "02", 2) == 0, "two outputs as built");
                /* value(8) script(1+25) then the second value */
                size_t val1 = nout_off + 2 + 16 + 2 + 50;
                memcpy(dusty + val1, "e803000000000000", 16);   /* 1000 koinu */
                CHECK(pc_tx_verify_payment(&ch, dusty, 2000000000ULL) == PC_ERR_DUST,
                      "an output under the hard dust limit is refused");
                free(dusty);
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

    /* ── the opening handshake ───────────────────────────────── */
    {
        /* Bob learns the channel from the script alone */
        char pa[PUBKEYHEXLEN], pb[PUBKEYHEXLEN];
        uint32_t lt = 0;
        CHECK_OK(pc_redeem_parse(ch.redeem_script_hex, pa, pb, &lt), "redeem parses");
        CHECK(strcmp(pa, alice_pub) == 0, "alice's key recovered");
        CHECK(strcmp(pb, bob_pub) == 0, "bob's key recovered");
        CHECK(lt == 300000, "locktime recovered, got %u", lt);

        CHECK(pc_redeem_parse("deadbeef", pa, pb, &lt) == PC_ERR_SCRIPT, "garbage refused");
        {   /* a trailing byte must not be ignored */
            char longer[PC_MAX_SCRIPT_HEX + 2];   /* room for the byte appended */
            snprintf(longer, sizeof(longer), "%s00", ch.redeem_script_hex);
            CHECK(pc_redeem_parse(longer, pa, pb, &lt) == PC_ERR_SCRIPT,
                  "trailing byte refused");
        }

        /* the funding output is derived, not asserted */
        char ftxid[65] = {0};
        int fvout = -1;
        uint64_t fval = 0;
        CHECK_OK(pc_tx_find_channel_output(&ch, funding_hex, ftxid, &fvout, &fval),
                 "channel output found");
        CHECK(strcmp(ftxid, funding_txid) == 0, "txid matches");
        CHECK(fvout == 0, "vout found, got %d", fvout);
        CHECK(fval == 10000000000ULL, "capacity read, got %" PRIu64, fval);

        /* a transaction that pays a different channel is not ours */
        CHECK(pc_tx_find_channel_output(&other, funding_hex, ftxid, &fvout, &fval)
                  == PC_ERR_AMOUNT, "another channel gets nothing");

        /* the opening psbt, and bob accepting it */
        char *open_psbt = NULL;
        CHECK_OK(pc_channel_open_create(&ch, funding_hex, &open_psbt), "open built");
        CHECK(open_psbt != NULL, "open psbt produced");
        if (open_psbt) {
            pc_channel bobs;
            CHECK_OK(pc_channel_init(&bobs, alice_pub, bob_pub, 300000, 0), "bob's view");
            uint64_t cap = 0;
            CHECK_OK(pc_channel_open_accept(&bobs, open_psbt, funding_hex,
                                            1000, 100, &cap), "bob accepts");
            CHECK(cap == 10000000000ULL, "bob read the capacity");
            CHECK(strcmp(bobs.funding_txid, funding_txid) == 0, "bob found the funding");

            /* a locktime that does not outlast the work is refused */
            pc_channel tight;
            CHECK_OK(pc_channel_init(&tight, alice_pub, bob_pub, 300000, 0), "tight init");
            CHECK(pc_channel_open_accept(&tight, open_psbt, funding_hex,
                                         299950, 100, &cap) == PC_ERR_STATE,
                  "locktime too near is refused");
            CHECK_OK(pc_channel_init(&tight, alice_pub, bob_pub, 300000, 0), "reinit");
            CHECK(pc_channel_open_accept(&tight, open_psbt, funding_hex,
                                         299899, 100, &cap) == PC_OK,
                  "one block of slack over the line is enough");

            /* an opening for someone else's channel is refused */
            pc_channel wrongbob;
            CHECK_OK(pc_channel_init(&wrongbob, alice_pub, alice_pub, 300000, 0), "wrong bob");
            CHECK(pc_channel_open_accept(&wrongbob, open_psbt, funding_hex,
                                         1000, 100, &cap) != PC_OK,
                  "an opening naming someone else is refused");

            dogecoin_free(open_psbt);
        }
    }

    /* ── the refund branch, the only way alice gets her money back ── */
    {
        char *refund = NULL;
        CHECK_OK(pc_refund_create(&ch, alice_wif, alice_addr, 100000000ULL, &refund),
                 "refund built");
        if (refund) {
            unsigned char rb[520];
            size_t rl2 = 0;
            utils_hex_to_bin(ch.redeem_script_hex, rb, strlen(ch.redeem_script_hex), &rl2);

            /* it spends the funding outpoint and pays alice */
            CHECK(strstr(refund, ch.redeem_script_hex) != NULL,
                  "refund carries the redeem script");

            size_t n2 = strlen(refund);
            /* nLockTime is the channel's, or CLTV has nothing to compare */
            char ltbuf[9];
            snprintf(ltbuf, sizeof(ltbuf), "%02x%02x%02x%02x",
                     ch.locktime & 0xff, (ch.locktime >> 8) & 0xff,
                     (ch.locktime >> 16) & 0xff, (ch.locktime >> 24) & 0xff);
            CHECK(memcmp(refund + n2 - 8, ltbuf, 8) == 0,
                  "refund locktime is the channel's");

            CHECK(pc_tx_verify_payment(&ch, refund, 1) != PC_OK,
                  "a refund is not a payment to bob");

            /* Parse the scriptSig rather than searching the hex: 0x51 turns up
               in a txid or inside a signature, so strstr() would pass on almost
               any transaction of this length.
                 version(8) inputs(2) txid(64) vout(8) = 82, then the scriptSig
               length, then <sig> OP_1 <redeem>. */
            unsigned char *rawb = NULL;
            size_t rawn = 0;
            CHECK(hex_bytes(refund, &rawb, &rawn), "refund decodes");
            if (rawb) {
                size_t o = 41;                       /* 4 + 1 + 32 + 4 bytes */
                size_t sslen = rawb[o++];
                CHECK(sslen < 0xfd, "refund scriptSig is short enough for one byte");
                size_t end = o + sslen;
                size_t siglen = rawb[o++];
                const unsigned char *sig = rawb + o;
                o += siglen;
                CHECK(siglen >= 9 && o < rawn, "refund carries one signature");
                CHECK(rawb[o] == 0x51, "the selector is OP_1, the IF branch");
                o++;
                size_t plen = rawb[o] == 0x4c ? (o += 2, rawb[o - 1]) : rawb[o++];
                CHECK(plen == rl2 && memcmp(rawb + o, rb, rl2) == 0,
                      "the pushed script is this channel's");
                CHECK(o + plen == end, "the scriptSig ends where it says");

                /* the signature actually verifies, which the digest alone does
                   not say */
                unsigned char h[32];
                CHECK_OK(pc_tx_sighash(refund, rb, rl2, h), "refund sighash");
                unsigned char apub[33];
                size_t an = 0;
                utils_hex_to_bin(ch.alice_pubkey_hex, apub, 66, &an);
                CHECK(an == 33, "alice's key decodes");
                CHECK(sig[siglen - 1] == 0x01, "hashtype is SIGHASH_ALL");
                CHECK(dogecoin_ecc_verify_sig(apub, true, h,
                                              (unsigned char *)sig, siglen - 1),
                      "alice's refund signature verifies");
                unsigned char h2[32];
                memcpy(h2, h, sizeof(h2));
                h2[0] ^= 0xff;
                CHECK(!dogecoin_ecc_verify_sig(apub, true, h2,
                                               (unsigned char *)sig, siglen - 1),
                      "and does not verify against a different digest");

                /* it pays alice's hash160, not merely someone's */
                uint8_t ad[64];
                CHECK(dogecoin_base58_decode_check(alice_addr, ad, sizeof(ad)) == 25,
                      "alice's address decodes");
                CHECK(memcmp(rawb + rawn - 26, ad + 1, 20) == 0,
                      "the refund output pays alice's hash160");
                free(rawb);
            }
            dogecoin_free(refund);
        }
        CHECK(pc_refund_create(&ch, alice_wif, alice_addr, 0, &refund) == PC_ERR_AMOUNT,
              "a zero-fee refund is refused");
        CHECK(pc_refund_create(&ch, alice_wif, alice_addr,
                               ch.capacity_koinu, &refund) == PC_ERR_AMOUNT,
              "a refund spending the whole capacity on fee is refused");
    }

    free(funding_hex);   /* the opening checks above still read it */

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

    /* the ack's continuation flag: it ends the payment loop, so a value that
       silently decodes wrong is a hang rather than an error */
    memset(&env, 0, sizeof(env));
    env.type = PC_MSG_ACK;
    env.more = 1;
    snprintf(env.psbt_hex, sizeof(env.psbt_hex), "01");
    CHECK_OK(pc_envelope_encode(&env, wire, sizeof(wire)), "ack encode");
    CHECK_OK(pc_envelope_decode(wire, &back), "ack decode");
    CHECK(back.more == 1, "more round-trips set");
    env.more = 0;
    CHECK_OK(pc_envelope_encode(&env, wire, sizeof(wire)), "final ack encode");
    CHECK_OK(pc_envelope_decode(wire, &back), "final ack decode");
    CHECK(back.more == 0, "more round-trips clear");
    env.more = 2;
    CHECK(pc_envelope_encode(&env, wire, sizeof(wire)) != PC_OK,
          "non-boolean more refused");
    CHECK(pc_envelope_decode("{\"type\":\"ack\",\"more\":7,\"psbt\":\"01\"}",
                             &back) != PC_OK, "out-of-range more refused");
    CHECK_OK(pc_envelope_decode("{\"type\":\"ack\",\"psbt\":\"01\"}", &back),
             "absent more accepted");
    CHECK(back.more == 0, "absent more reads as no");

    /* every reject reason has spaces in it, so a field held to base58's
       alphabet could not carry one and the peer got a dead socket instead */
    memset(&env, 0, sizeof(env));
    env.type = PC_MSG_REJECT;
    snprintf(env.addr, sizeof(env.addr), "%s", "not a channel script");
    snprintf(env.psbt_hex, sizeof(env.psbt_hex), "01");
    CHECK_OK(pc_envelope_encode(&env, wire, sizeof(wire)), "reject reason encodes");
    CHECK_OK(pc_envelope_decode(wire, &back), "reject reason decodes");
    CHECK(strcmp(back.addr, env.addr) == 0, "reject reason round-trips");

    snprintf(env.addr, sizeof(env.addr), "%s", "has\"quote");
    CHECK(pc_envelope_encode(&env, wire, sizeof(wire)) != PC_OK,
          "a quote in the reason is refused");

    CHECK(pc_envelope_decode("{\"type\":\"ack\",\"to_bob\":1,\"to_bob\":2,\"psbt\":\"01\"}",
                             &back) != PC_OK, "a repeated key is refused");
    CHECK(pc_envelope_decode("{\"type\":\"ack\",\"to_bob\":-1,\"psbt\":\"01\"}",
                             &back) != PC_OK, "a negative amount is refused");
    CHECK(pc_envelope_decode("{\"type\":\"ack\",\"to_bob\":12x,\"psbt\":\"01\"}",
                             &back) != PC_OK, "a bad amount terminator is refused");

    /* bob sends pc_strerror() as a reject reason, so every one of them has to
       survive the envelope. a comma in one of these is how the reject path went
       dead the first time. */
    for (int e = PC_OK; e <= PC_ERR_FINAL + 1; e++) {
        memset(&env, 0, sizeof(env));
        env.type = PC_MSG_REJECT;
        snprintf(env.addr, sizeof(env.addr), "%s", pc_strerror((pc_result)e));
        snprintf(env.psbt_hex, sizeof(env.psbt_hex), "01");
        CHECK(pc_envelope_encode(&env, wire, sizeof(wire)) == PC_OK,
              "pc_strerror(%d) survives the envelope: %s", e, pc_strerror((pc_result)e));
    }

done:
    dogecoin_ecc_stop();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
