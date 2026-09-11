/* pc's SIGHASH_ALL digest against signatures it did not produce.
 *
 * src/txcheck.c computes the legacy sighash itself, and koinu computes it
 * independently, and Bob checks his own signature against pc's digest so the
 * two cannot drift apart quietly. That catches drift, not a shared misreading:
 * both implementations are ours, so an error in how we read the rules is in
 * both of them and neither one contradicts the other.
 *
 * These are the outside opinion. Every vector carries a signature somebody else
 * already validated against the digest consensus really uses, so recomputing
 * that digest and checking the signature against it is a test no wrong answer
 * passes by coincidence.
 *
 * Two sources, from test/mkvectors.py and test/mkvectors_chain.py:
 *
 *   sighash_vectors        transactions Dogecoin Core's own tx_valid.json
 *                          asserts are valid. Few, and deliberately strange.
 *   sighash_vectors_chain  confirmed mainnet spends, in both shapes pc takes a
 *                          digest over: P2PKH, where the script code is the
 *                          scriptPubKey, and P2SH, where it is the redeem
 *                          script the scriptSig pushes last. The second is the
 *                          shape pc's own 2-of-2 channel uses.
 *
 * Both are checked in, so this needs no python, no node and no network. */

#include "channel.h"
#include "hex.h"
#include "ec.h"

#include <stdio.h>
#include <string.h>

#define LINE_MAX_LEN 16384
#define MAX_ITEMS    16
#define SHOW_FAILURES 5

/* Two sources, because they fail differently. Core's tx_valid.json is a handful
   of odd script shapes someone wrote deliberately; the chain file is bulk
   ordinary spending that the network actually validated. A digest bug that
   somehow survived one is unlikely to survive both. */
static const char *DEFAULT_PATHS[] = {
    "test/data/sighash_vectors",
    "test/data/sighash_vectors_chain",
};

/* Split (s) on commas in place, filling (out) with the pieces. */
static size_t split_csv(char *s, char **out, size_t cap)
{
    size_t n = 0;
    for (char *tok = strtok(s, ","); tok && n < cap; tok = strtok(NULL, ","))
        out[n++] = tok;
    return n;
}

/* Hex to bytes into a fixed buffer, refusing anything that will not fit. */
static int hex_bytes(const char *hex, unsigned char *out, size_t cap, size_t *len)
{
    size_t hl = strlen(hex);
    if (hl == 0 || (hl % 2) || hl / 2 > cap) return 0;
    if (!pc_hex_to_bin(hex, out, hl / 2)) return 0;
    *len = hl / 2;
    return 1;
}

/* One vector file. Adds its counts to (*total_out) and (*ok_out) and returns
   non-zero only if the file could not be read at all; a vector that fails to
   verify is reported through the counts, so every file is still walked. */
static int run_file(const char *path, int *total_out, int *ok_out)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "sighash-vectors: cannot open %s\n", path);
        return 1;
    }

    char line[LINE_MAX_LEN];
    int total = 0, ok = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char *code_hex = strtok(line, " \t\n");
        char *keys_s   = strtok(NULL, " \t\n");
        char *sigs_s   = strtok(NULL, " \t\n");
        char *raw_hex  = strtok(NULL, " \t\n");
        if (!code_hex || !keys_s || !sigs_s || !raw_hex) continue;

        total++;

        unsigned char code[520];
        size_t clen = 0;
        if (!hex_bytes(code_hex, code, sizeof(code), &clen)) {
            printf("  %-3d script code will not decode\n", total);
            continue;
        }

        /* The digest under test. Everything after this is only deciding
           whether consensus agrees with it. */
        unsigned char hash[32];
        if (pc_tx_sighash(raw_hex, code, clen, hash) != PC_OK) {
            printf("  %-3d pc_tx_sighash refused the transaction\n", total);
            continue;
        }

        /* strtok is already in use on the line, so the lists are split after
           every field above has been taken off it. */
        char *keys[MAX_ITEMS], *sigs[MAX_ITEMS];
        size_t nk = split_csv(keys_s, keys, MAX_ITEMS);
        char sigs_copy[LINE_MAX_LEN / 2];
        snprintf(sigs_copy, sizeof(sigs_copy), "%s", sigs_s);
        size_t ns = split_csv(sigs_copy, sigs, MAX_ITEMS);

        /* Which key signed which is not recorded, so the assertion is that
           EVERY signature verifies against some key in the script. A 2-of-2
           carries two, and "one of them verified" would pass on half a digest;
           requiring all of them is what makes a multisig vector worth more
           than a single-signature one. A wrong digest satisfies none. */
        size_t matched = 0;
        for (size_t j = 0; j < ns; j++) {
            unsigned char sig[80];
            size_t slen = 0;
            if (!hex_bytes(sigs[j], sig, sizeof(sig), &slen)) continue;
            for (size_t i = 0; i < nk; i++) {
                unsigned char raw[65], pub[33];
                size_t rlen = 0;
                if (!hex_bytes(keys[i], raw, sizeof(raw), &rlen)) continue;
                if (!kw_ec_pubkey_parse(raw, rlen, pub)) continue;
                if (kw_ec_verify(pub, hash, sig, slen)) { matched++; break; }
            }
        }
        int verified = (ns > 0 && matched == ns);

        /* Only failures are printed, and only the first few. A hundred and
           fifty lines of "verified" is not a result anyone reads, and a
           hundred and fifty failures are all one bug: the count below says how
           many were not shown, so the cap never reads as a clean run. */
        if (verified) {
            ok++;
        } else if (total - ok <= SHOW_FAILURES) {
            char hh[65];
            pc_bin_to_hex(hash, 32, hh);
            printf("  %s:%d NO SIGNATURE VERIFIES digest=%s\n", path, total, hh);
        }
    }
    fclose(f);

    if (total - ok > SHOW_FAILURES)
        printf("  ... and %d more failures not shown\n",
               total - ok - SHOW_FAILURES);

    if (total == 0) {
        fprintf(stderr, "sighash-vectors: no vectors in %s\n", path);
        return 1;
    }
    printf("  %-42s %d/%d\n", path, ok, total);
    *total_out += total;
    *ok_out += ok;
    return 0;
}

int main(int argc, char **argv)
{
    if (!kw_ec_start()) {
        fprintf(stderr, "sighash-vectors: no ec context\n");
        return 1;
    }
    printf("pc's digest against signatures it did not produce:\n");

    int total = 0, ok = 0, unreadable = 0;
    if (argc > 1) {
        for (int i = 1; i < argc; i++)
            unreadable |= run_file(argv[i], &total, &ok);
    } else {
        for (size_t i = 0; i < sizeof(DEFAULT_PATHS) / sizeof(*DEFAULT_PATHS); i++)
            unreadable |= run_file(DEFAULT_PATHS[i], &total, &ok);
    }

    kw_ec_stop();
    if (unreadable || total == 0) return 1;
    printf("%d/%d external vectors verify against pc's digest\n", ok, total);
    return ok == total ? 0 : 1;
}
