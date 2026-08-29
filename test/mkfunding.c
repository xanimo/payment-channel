/* Mint a funding transaction without a node, so the loopback test can drive
 * alice and bob against each other. The transaction is never broadcast and its
 * input does not exist: nothing in the protocol verifies the funding, that is
 * the operator's job and contrib/regtest.sh is where it happens for real.
 *
 * Prints: <hex> <txid> <vout> */

#include "channel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "--keys")) {
        /* generatePrivPubKeypair() takes a boolean, so it cannot produce a
           regtest wif: regtest's 0xef prefix is neither mainnet's nor
           testnet's. Go through the chainparams directly. */
        pc_chain which = PC_CHAIN_MAIN;
        if (argc == 3 && !strcmp(argv[2], "--testnet")) which = PC_CHAIN_TEST;
        if (argc == 3 && !strcmp(argv[2], "--regtest")) which = PC_CHAIN_REGTEST;
        const dogecoin_chainparams *chain = pc_chainparams(which);

        dogecoin_ecc_start();
        int ok = 0;
        dogecoin_key key;
        dogecoin_privkey_init(&key);
        if (dogecoin_privkey_gen(&key)) {
            char wif[PRIVKEYWIFLEN], addr[P2PKHLEN];
            size_t wlen = sizeof(wif);
            dogecoin_privkey_encode_wif(&key, chain, wif, &wlen);
            dogecoin_pubkey pub;
            dogecoin_pubkey_init(&pub);
            pub.compressed = true;
            dogecoin_pubkey_from_key(&key, &pub);
            if (dogecoin_pubkey_getaddr_p2pkh(&pub, chain, addr)) {
                printf("%s %s\n", wif, addr);
                ok = 1;
            }
        }
        dogecoin_privkey_cleanse(&key);
        dogecoin_ecc_stop();
        return ok ? 0 : 1;
    }
    if (argc != 4) {
        fprintf(stderr, "usage: mkfunding P2SH_ADDR CHANGE_ADDR DOGE\n"
                        "       mkfunding --keys [--testnet|--regtest]\n");
        return 2;
    }
    const char *p2sh = argv[1], *change = argv[2], *amount = argv[3];

    dogecoin_ecc_start();
    int rc = 1;

    uint64_t koinu = 0;
    if (pc_doge_to_koinu(amount, &koinu) != PC_OK) {
        fprintf(stderr, "mkfunding: bad amount\n");
        goto done;
    }
    char total[32];
    pc_koinu_to_doge(koinu + 200000000ULL, total, sizeof(total));  /* fee + change */

    int tix = start_transaction();
    if (tix < 0) goto done;
    if (!add_utxo(tix,
        (char *)"b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074", 0))
        goto done;
    if (!add_output(tix, (char *)p2sh, (char *)amount)) goto done;

    char *hex = (char *)malloc(DOGECOIN_MAX_TX_HEX_LEN);
    if (!hex) goto done;
    if (!finalize_transaction_ex(tix, (char *)p2sh, (char *)"1.0", total,
                                 (char *)change, hex, DOGECOIN_MAX_TX_HEX_LEN)) {
        free(hex);
        goto done;
    }

    size_t hl = strlen(hex), blen = 0;
    unsigned char *b = (unsigned char *)malloc(hl / 2 + 1);
    if (!b) { free(hex); goto done; }
    utils_hex_to_bin(hex, b, hl, &blen);
    dogecoin_tx *tx = dogecoin_tx_new();
    dogecoin_tx_deserialize(b, blen, tx, NULL);
    free(b);

    uint256_t txid;
    dogecoin_tx_hash(tx, txid);
    dogecoin_tx_free(tx);
    unsigned char rev[32];
    for (int i = 0; i < 32; i++) rev[i] = txid[31 - i];
    char txid_hex[65];
    utils_bin_to_hex(rev, 32, txid_hex);

    /* add_output() put the channel first, so it is output zero */
    printf("%s %s 0\n", hex, txid_hex);
    free(hex);
    remove_all();
    rc = 0;
done:
    dogecoin_ecc_stop();
    return rc;
}
