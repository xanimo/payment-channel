/* koinu shims for the libdogecoin key helpers the test and fuzz harnesses were
   written against, kept under the same names and shapes so their call sites do
   not change. Header-only; each translation unit gets its own static copy. */
#ifndef PC_KWSHIM_H
#define PC_KWSHIM_H

#include "channel.h"
#include "hex.h"
#include "ec.h"
#include "address.h"
#include "base58.h"
#include "rng.h"

#include <stdbool.h>
#include <string.h>

static inline int generatePrivPubKeypair(char *wif, char *addr, int is_test)
{
    uint8_t sk[32], pub[33];
    if (!kw_random_bytes(sk, sizeof(sk)) || !kw_ec_pubkey(sk, pub)) return 0;
    const kw_chainparams *cp = is_test ? &KW_DOGE_TESTNET : &KW_DOGE_MAINNET;
    int ok = kw_wif_encode(sk, 1, cp->wif, wif, PRIVKEYWIFLEN) &&
             (!addr || kw_address_p2pkh(pub, cp->p2pkh, addr, P2PKHLEN));
    { volatile uint8_t *z = sk; for (int i = 0; i < 32; i++) z[i] = 0; }
    return ok;
}

static inline int getPubkeyFromPrivkey(const char *wif, int is_test,
                                       char *pubhex, size_t *plen)
{
    (void)is_test;
    uint8_t sk[32], pub[33];
    int comp = 0;
    uint8_t ver = 0;
    int ok = kw_wif_decode(wif, sk, &comp, &ver) && kw_ec_pubkey(sk, pub);
    { volatile uint8_t *z = sk; for (int i = 0; i < 32; i++) z[i] = 0; }
    if (!ok) return 0;
    pc_bin_to_hex(pub, 33, pubhex);
    if (plen) *plen = 66;
    return 1;
}

#endif /* PC_KWSHIM_H */
