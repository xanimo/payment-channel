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

/* The paying side.
 *
 * Alice's amounts are cumulative: --pay 10 --pay 25 means Bob ends up holding a
 * transaction that pays him 25, not 35. That is the whole trick, and it is why
 * this only works in one direction. Each payment is a fresh transaction
 * spending the same funding output, so the earlier ones simply stop mattering.
 *
 * Alice must not sign a payment until the funding transaction is confirmed:
 * without SegWit the funding txid can still change, which would leave every
 * payment she has signed pointing at an output that no longer exists. */

#include "common.h"

#include <ctype.h>
#include <inttypes.h>
#include <unistd.h>

static void usage(void)
{
    fprintf(stderr,
      "usage: alice --wif WIF --peer-pubkey HEX --locktime N\n"
      "             --funding TXID:VOUT --funding-tx HEX|@FILE --capacity DOGE\n"
      "             --pay DOGE [--pay DOGE ...] [--fee DOGE] [--close]\n"
      "             [--connect [HOST:]PORT] [--testnet]\n"
      "       alice --wif WIF --pubkey\n"
      "       alice --wif WIF --peer-pubkey HEX --locktime N --address\n"
      "\n"
      "  --pay amounts are cumulative totals paid to Bob, and must increase.\n"
      "  Fund --address first and wait for confirmations before paying.\n");
}

#define MAX_PAYMENTS 64

int main(int argc, char **argv)
{
    const char *wif = NULL, *peer = NULL, *funding = NULL, *cap_s = NULL;
    const char *ftx_arg = NULL, *connect_to = NULL, *fee_s = "1.0";
    const char *pays[MAX_PAYMENTS];
    int npays = 0;
    uint32_t locktime = 0;
    int testnet = 0, want_pubkey = 0, want_address = 0, want_close = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : NULL)
        if      (!strcmp(a, "--wif"))         wif = NEXT();
        else if (!strcmp(a, "--peer-pubkey")) peer = NEXT();
        else if (!strcmp(a, "--funding"))     funding = NEXT();
        else if (!strcmp(a, "--funding-tx"))  ftx_arg = NEXT();
        else if (!strcmp(a, "--capacity"))    cap_s = NEXT();
        else if (!strcmp(a, "--fee"))         fee_s = NEXT();
        else if (!strcmp(a, "--connect"))     connect_to = NEXT();
        else if (!strcmp(a, "--locktime"))    { const char *v = NEXT(); locktime = v ? (uint32_t)strtoul(v, NULL, 10) : 0; }
        else if (!strcmp(a, "--testnet"))     testnet = 1;
        else if (!strcmp(a, "--pubkey"))      want_pubkey = 1;
        else if (!strcmp(a, "--address"))     want_address = 1;
        else if (!strcmp(a, "--close"))       want_close = 1;
        else if (!strcmp(a, "--pay")) {
            const char *v = NEXT();
            if (!v || npays == MAX_PAYMENTS) { usage(); return 2; }
            pays[npays++] = v;
        }
        else { usage(); return 2; }
        #undef NEXT
    }
    if (!wif || !fee_s) { usage(); return 2; }

    dogecoin_ecc_start();
    int rc = 1, fd = -1;
    char *funding_tx = NULL;

    char alice_pub[PUBKEYHEXLEN], alice_addr[P2PKHLEN];
    if (!pc_identity(wif, testnet, alice_pub, alice_addr)) {
        fprintf(stderr, "alice: wif would not decode\n");
        goto done;
    }
    if (want_pubkey) { printf("%s\n", alice_pub); rc = 0; goto done; }

    if (!peer || !locktime) { usage(); goto done; }

    pc_channel ch;
    pc_result r = pc_channel_init(&ch, alice_pub, peer, locktime, testnet);
    if (r != PC_OK) {
        fprintf(stderr, "alice: channel: %s\n", pc_strerror(r));
        goto done;
    }
    if (want_address) { printf("%s\n", ch.p2sh_address); rc = 0; goto done; }

    if (!funding || !ftx_arg || !cap_s || npays == 0) { usage(); goto done; }

    char txid[65];
    int vout = 0;
    if (!pc_split_outpoint(funding, txid, &vout)) {
        fprintf(stderr, "alice: --funding wants TXID:VOUT\n");
        goto done;
    }
    uint64_t capacity = 0, fee = 0;
    if (pc_doge_to_koinu(cap_s, &capacity) != PC_OK ||
        pc_doge_to_koinu(fee_s, &fee) != PC_OK) {
        fprintf(stderr, "alice: --capacity or --fee is not an amount\n");
        goto done;
    }
    funding_tx = pc_read_hex_arg(ftx_arg);
    if (!funding_tx) { fprintf(stderr, "alice: cannot read --funding-tx\n"); goto done; }

    r = pc_channel_set_funding(&ch, txid, vout, capacity);
    if (r != PC_OK) { fprintf(stderr, "alice: funding: %s\n", pc_strerror(r)); goto done; }

    /* Bob's p2pkh address comes from the pubkey in the channel, so a payment
       can only ever be addressed to the key the channel was built around. */
    char bob_addr[P2PKHLEN];
    {
        dogecoin_pubkey bp;
        dogecoin_pubkey_init(&bp);
        bp.compressed = true;
        size_t n = 0;
        utils_hex_to_bin(ch.bob_pubkey_hex, bp.pubkey, 66, &n);
        if (n != 33 || !dogecoin_pubkey_getaddr_p2pkh(&bp,
                testnet ? &dogecoin_chainparams_test : &dogecoin_chainparams_main,
                bob_addr)) {
            fprintf(stderr, "alice: peer pubkey is not a usable key\n");
            goto done;
        }
    }

    char host[64] = "127.0.0.1";
    int port = PC_DEFAULT_PORT;
    if (connect_to) {
        port = pc_wire_split(connect_to, host, sizeof(host), PC_DEFAULT_PORT);
        if (port < 0) { fprintf(stderr, "alice: bad --connect\n"); goto done; }
        if (!host[0]) snprintf(host, sizeof(host), "127.0.0.1");
    }
    fd = pc_wire_connect(host, port);
    if (fd < 0) { fprintf(stderr, "alice: cannot reach %s:%d\n", host, port); goto done; }

    printf("channel  %s\n", ch.p2sh_address);
    printf("paying   %s\n", bob_addr);
    printf("funding  %s:%d\n\n", ch.funding_txid, ch.funding_vout);

    pc_envelope out, in;
    pc_announce(&out, alice_pub, locktime);
    if (!pc_wire_send(fd, &out)) { fprintf(stderr, "alice: send failed\n"); goto done; }
    if (pc_wire_recv(fd, &in) != 1 || in.type != PC_MSG_ANNOUNCE) {
        fprintf(stderr, "alice: peer did not announce\n");
        goto done;
    }
    /* The pubkey was pinned on the command line, so a substituted one here is
       an attacker on the socket rather than a disagreement. */
    if (strcmp(in.psbt_hex, ch.bob_pubkey_hex) != 0) {
        fprintf(stderr, "alice: peer announced a different pubkey, refusing\n");
        goto done;
    }

    uint64_t last = 0;
    for (int i = 0; i < npays; i++) {
        uint64_t total = 0;
        if (pc_doge_to_koinu(pays[i], &total) != PC_OK) {
            fprintf(stderr, "alice: --pay %s is not an amount\n", pays[i]);
            goto done;
        }
        if (total <= last) {
            fprintf(stderr, "alice: --pay amounts are cumulative and must grow\n");
            goto done;
        }
        last = total;

        char *psbt = NULL;
        r = pc_payment_create(&ch, funding_tx, wif, alice_addr, bob_addr,
                              total, fee, &psbt);
        if (r != PC_OK) {
            fprintf(stderr, "alice: payment: %s\n", pc_strerror(r));
            goto done;
        }

        memset(&out, 0, sizeof(out));
        out.type = PC_MSG_PAYMENT;
        snprintf(out.ref, sizeof(out.ref), "%s", ch.funding_txid);
        out.to_bob_koinu = total;
        if (strlen(psbt) + 1 > sizeof(out.psbt_hex)) {
            fprintf(stderr, "alice: psbt does not fit an envelope\n");
            dogecoin_free(psbt);
            goto done;
        }
        snprintf(out.psbt_hex, sizeof(out.psbt_hex), "%s", psbt);
        dogecoin_free(psbt);

        if (!pc_wire_send(fd, &out)) { fprintf(stderr, "alice: send failed\n"); goto done; }
        if (pc_wire_recv(fd, &in) != 1 || in.type != PC_MSG_ACK) {
            fprintf(stderr, "alice: payment of %s was not acknowledged\n", pays[i]);
            goto done;
        }
        if (in.to_bob_koinu != total) {
            fprintf(stderr, "alice: peer acknowledged %" PRIu64 ", not %" PRIu64 "\n",
                    in.to_bob_koinu, total);
            goto done;
        }
        printf("paid %s DOGE (cumulative)\n", pays[i]);
        fflush(stdout);
    }

    if (want_close) {
        memset(&out, 0, sizeof(out));
        out.type = PC_MSG_CLOSE;
        snprintf(out.ref, sizeof(out.ref), "%s", ch.funding_txid);
        out.to_bob_koinu = last;
        snprintf(out.psbt_hex, sizeof(out.psbt_hex), "01");
        if (!pc_wire_send(fd, &out)) { fprintf(stderr, "alice: send failed\n"); goto done; }
        if (pc_wire_recv(fd, &in) != 1 || in.type != PC_MSG_CLOSE) {
            fprintf(stderr, "alice: peer would not close\n");
            goto done;
        }
        printf("\nclosing transaction, either side can broadcast it:\n%s\n", in.psbt_hex);
    }

    rc = 0;
done:
    if (fd >= 0) close(fd);
    free(funding_tx);
    dogecoin_ecc_stop();
    return rc;
}
