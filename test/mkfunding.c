/* Mint a funding transaction without a node, so the loopback test can drive
 * alice and bob against each other. The transaction is never broadcast and its
 * input does not exist: nothing in the protocol verifies the funding, that is
 * the operator's job and contrib/regtest.sh is where it happens for real.
 *
 * Prints: <hex> <txid> <vout>
 *
 * On koinu (libkw): keys through kw_random_bytes/kw_ec_pubkey/kw_wif_encode and
 * the transaction through kw_tx, so this carries no libdogecoin dependency. */

#include "channel.h"
#include "hex.h"
#include "ec.h"
#include "address.h"
#include "base58.h"
#include "tx.h"
#include "rng.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "--keys")) {
        pc_chain which = PC_CHAIN_MAIN;
        if (argc == 3 && !strcmp(argv[2], "--testnet")) which = PC_CHAIN_TEST;
        if (argc == 3 && !strcmp(argv[2], "--regtest")) which = PC_CHAIN_REGTEST;
        const kw_chainparams *cp = pc_chainparams(which);

        kw_ec_start();
        int ok = 0;
        uint8_t sk[32], pub[33];
        if (kw_random_bytes(sk, sizeof(sk)) && kw_ec_pubkey(sk, pub)) {
            char wif[PRIVKEYWIFLEN], addr[P2PKHLEN];
            if (kw_wif_encode(sk, 1, cp->wif, wif, sizeof(wif)) &&
                kw_address_p2pkh(pub, cp->p2pkh, addr, sizeof(addr))) {
                printf("%s %s\n", wif, addr);
                ok = 1;
            }
        }
        { volatile uint8_t *z = sk; for (int i = 0; i < 32; i++) z[i] = 0; }
        kw_ec_stop();
        return ok ? 0 : 1;
    }
    if (argc != 4) {
        fprintf(stderr, "usage: mkfunding P2SH_ADDR CHANGE_ADDR DOGE\n"
                        "       mkfunding --keys [--testnet|--regtest]\n");
        return 2;
    }
    const char *p2sh = argv[1], *change = argv[2], *amount = argv[3];

    uint64_t koinu = 0;
    if (pc_doge_to_koinu(amount, &koinu) != PC_OK) {
        fprintf(stderr, "mkfunding: bad amount\n");
        return 1;
    }

    /* the p2sh address to its scriptPubKey, and the change address to a hash160 */
    uint8_t praw[64], craw[64];
    size_t pn = 0, cn = 0;
    if (!kw_base58check_decode(p2sh, praw, sizeof(praw), &pn) || pn != 21 ||
        !kw_base58check_decode(change, craw, sizeof(craw), &cn) || cn != 21) {
        fprintf(stderr, "mkfunding: bad address\n");
        return 1;
    }
    uint8_t p2sh_spk[23];
    p2sh_spk[0] = 0xa9; p2sh_spk[1] = 0x14;
    memcpy(p2sh_spk + 2, praw + 1, 20);
    p2sh_spk[22] = 0x87;

    /* one dummy input, the channel output first (so it is vout 0), then a token
       change output. It is never signed or broadcast. */
    kw_tx tx;
    kw_tx_init(&tx);
    if (!kw_tx_add_input(&tx,
        "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074", 0))
        return 1;
    if (!kw_tx_add_output(&tx, koinu, p2sh_spk, sizeof(p2sh_spk))) return 1;
    if (!kw_tx_add_output_p2pkh(&tx, 100000000ULL, craw + 1)) return 1;

    uint8_t raw[8192];
    size_t n = kw_tx_serialize(&tx, raw, sizeof(raw));
    if (n == 0) return 1;
    char *hex = (char *)malloc(n * 2 + 1);
    if (!hex) return 1;
    pc_bin_to_hex(raw, n, hex);

    uint8_t txid[32], rev[32];
    if (!kw_tx_txid(&tx, txid)) { free(hex); return 1; }
    for (int i = 0; i < 32; i++) rev[i] = txid[31 - i];
    char txid_hex[65];
    pc_bin_to_hex(rev, 32, txid_hex);

    printf("%s %s 0\n", hex, txid_hex);
    free(hex);
    return 0;
}
