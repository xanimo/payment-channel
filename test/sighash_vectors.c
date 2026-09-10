/* pc's SIGHASH_ALL digest against Dogecoin Core's consensus test data.
 *
 * src/txcheck.c computes the legacy sighash itself, and koinu computes it
 * independently, and Bob checks his own signature against pc's digest so the
 * two cannot drift apart quietly. That catches drift, not a shared misreading:
 * both implementations are ours, so an error in how we read the rules is in
 * both of them and neither one contradicts the other.
 *
 * This is the outside opinion. Every vector is a transaction Dogecoin Core's
 * own test suite asserts is valid, so a miner's script interpreter accepted its
 * signature, so that signature verifies against the digest consensus actually
 * uses and nothing else. pc recomputes the digest and checks the signature
 * against it: a digest that differs from consensus in any way fails to verify,
 * and cannot pass by coincidence.
 *
 * The vectors are derived by test/mkvectors.py and checked in, so this needs no
 * python and no network. See that file for how they are selected. */

#include "channel.h"
#include "hex.h"
#include "ec.h"

#include <stdio.h>
#include <string.h>

#define LINE_MAX_LEN 16384
#define MAX_ITEMS    16

static const char *DEFAULT_PATH = "test/data/sighash_vectors";

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

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : DEFAULT_PATH;
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "sighash-vectors: cannot open %s\n", path);
        return 1;
    }
    if (!kw_ec_start()) {
        fprintf(stderr, "sighash-vectors: no ec context\n");
        fclose(f);
        return 1;
    }

    printf("pc's digest against dogecoin core's tx_valid.json:\n");

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

        /* Which key signed is not recorded in the data, so any pair verifying
           is the assertion. A wrong digest satisfies none of them. */
        int verified = 0;
        for (size_t i = 0; i < nk && !verified; i++) {
            unsigned char raw[65], pub[33];
            size_t rlen = 0;
            if (!hex_bytes(keys[i], raw, sizeof(raw), &rlen)) continue;
            if (!kw_ec_pubkey_parse(raw, rlen, pub)) continue;
            for (size_t j = 0; j < ns && !verified; j++) {
                unsigned char sig[80];
                size_t slen = 0;
                if (!hex_bytes(sigs[j], sig, sizeof(sig), &slen)) continue;
                if (kw_ec_verify(pub, hash, sig, slen)) verified = 1;
            }
        }

        if (verified) {
            ok++;
            printf("  %-3d verified against consensus\n", total);
        } else {
            char hh[65];
            pc_bin_to_hex(hash, 32, hh);
            printf("  %-3d NO SIGNATURE VERIFIES digest=%s\n", total, hh);
        }
    }

    kw_ec_stop();
    fclose(f);

    if (total == 0) {
        fprintf(stderr, "sighash-vectors: no vectors in %s\n", path);
        return 1;
    }
    printf("%d/%d core vectors verify against pc's digest\n", ok, total);
    return ok == total ? 0 : 1;
}
