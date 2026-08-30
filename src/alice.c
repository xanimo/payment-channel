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

/* The customer.
 *
 * Alice asks for a channel, gets back the key Bob will sign with, builds the
 * P2SH from it, and funds it. From then on she pays what Bob invoices, and the
 * invoices are cumulative: a bill for 10 then 15 means Bob ends up holding one
 * transaction paying him 25, not two paying 10 and 15. That is the whole trick,
 * and it is why the channel only runs one way. Each payment spends the same
 * funding output, so the earlier ones simply stop mattering.
 *
 * Two modes. --address prints the channel address to fund and stops, because
 * funding has to confirm before anything is signed against it: without SegWit
 * the funding txid is still malleable, and a payment signed against an
 * unconfirmed one points at an outpoint that can cease to exist. --funding-tx
 * then runs the channel against that confirmed transaction. */

#include "common.h"

#include <ctype.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>

static void usage(void)
{
    fprintf(stderr,
      "usage: alice --wif WIF --peer-pubkey HEX --locktime N --address\n"
      "       alice --wif WIF --locktime N --funding-tx HEX|@FILE\n"
      "             [--peer-pubkey HEX] [--fee DOGE] [--max DOGE] [--close]\n"
      "             [--connect [HOST:]PORT] [--testnet|--regtest]\n"
      "       alice --wif WIF --pubkey\n"
      "\n"
      "  Fund --address and let it confirm before running the second form.\n"
      "  --peer-pubkey pins Bob's key; without it Alice trusts what he answers.\n"
      "  --max refuses to pay more than that in total.\n"
      "  --refund builds Alice's unilateral close, valid once --locktime\n"
      "  passes. It needs no peer, which is the situation it is for.\n");
}

int main(int argc, char **argv)
{
    const char *wif = NULL, *peer = NULL, *ftx_arg = NULL;
    const char *connect_to = NULL, *fee_s = "1.0", *max_s = NULL;
    uint32_t locktime = 0;
    pc_chain chain = PC_CHAIN_MAIN;
    int want_pubkey = 0, want_address = 0, want_close = 0, want_refund = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : NULL)
        if      (!strcmp(a, "--wif"))         wif = NEXT();
        else if (!strcmp(a, "--peer-pubkey")) peer = NEXT();
        else if (!strcmp(a, "--funding-tx"))  ftx_arg = NEXT();
        else if (!strcmp(a, "--fee"))         fee_s = NEXT();
        else if (!strcmp(a, "--max"))         max_s = NEXT();
        else if (!strcmp(a, "--connect"))     connect_to = NEXT();
        else if (!strcmp(a, "--locktime"))    { const char *v = NEXT(); locktime = v ? (uint32_t)strtoul(v, NULL, 10) : 0; }
        else if (!strcmp(a, "--testnet"))     chain = PC_CHAIN_TEST;
        else if (!strcmp(a, "--regtest"))     chain = PC_CHAIN_REGTEST;
        else if (!strcmp(a, "--pubkey"))      want_pubkey = 1;
        else if (!strcmp(a, "--address"))     want_address = 1;
        else if (!strcmp(a, "--close"))       want_close = 1;
        else if (!strcmp(a, "--refund"))      want_refund = 1;
        else { usage(); return 2; }
        #undef NEXT
    }
    if (!wif || !fee_s) { usage(); return 2; }

    /* a peer that closes mid-write must not take the process with it */
    signal(SIGPIPE, SIG_IGN);

    dogecoin_ecc_start();
    int rc = 1, fd = -1;
    char *funding_tx = NULL;

    char alice_pub[PUBKEYHEXLEN], alice_addr[P2PKHLEN];
    if (!pc_identity(wif, chain, alice_pub, alice_addr)) {
        fprintf(stderr, "alice: wif would not decode\n");
        goto done;
    }
    if (want_pubkey) { printf("%s\n", alice_pub); rc = 0; goto done; }
    if (!locktime) { usage(); goto done; }

    pc_channel ch;
    pc_result r;

    /* First form: Bob's key is already known, print where to send the money. */
    if (want_address) {
        if (!peer) { usage(); goto done; }
        r = pc_channel_init(&ch, alice_pub, peer, locktime, chain);
        if (r != PC_OK) { fprintf(stderr, "alice: channel: %s\n", pc_strerror(r)); goto done; }
        printf("%s\n", ch.p2sh_address);
        rc = 0;
        goto done;
    }
    if (!ftx_arg) { usage(); goto done; }

    uint64_t fee = 0, maximum = UINT64_MAX;
    if (pc_doge_to_koinu(fee_s, &fee) != PC_OK) {
        fprintf(stderr, "alice: --fee is not an amount\n"); goto done;
    }

    /* The refund needs no peer on the other end, which is the whole point of
       it: Bob is gone. It needs his key only to rebuild the script. */
    if (want_refund) {
        if (!peer) { usage(); goto done; }
        funding_tx = pc_read_hex_arg(ftx_arg);
        if (!funding_tx) { fprintf(stderr, "alice: cannot read --funding-tx\n"); goto done; }
        r = pc_channel_init(&ch, alice_pub, peer, locktime, chain);
        if (r != PC_OK) { fprintf(stderr, "alice: channel: %s\n", pc_strerror(r)); goto done; }

        char rtxid[65] = {0};
        int rvout = 0;
        uint64_t rcap = 0;
        r = pc_tx_find_channel_output(&ch, funding_tx, rtxid, &rvout, &rcap);
        if (r != PC_OK) {
            fprintf(stderr, "alice: --funding-tx does not pay %s\n", ch.p2sh_address);
            goto done;
        }
        r = pc_channel_set_funding(&ch, rtxid, rvout, rcap);
        if (r != PC_OK) { fprintf(stderr, "alice: funding: %s\n", pc_strerror(r)); goto done; }

        char *refund = NULL;
        r = pc_refund_create(&ch, wif, alice_addr, fee, &refund);
        if (r != PC_OK) { fprintf(stderr, "alice: refund: %s\n", pc_strerror(r)); goto done; }
        /* IsFinalTx wants nLockTime < nBlockHeight, so a transaction with
           nLockTime == locktime first becomes final in the block after it */
        printf("refund transaction, spendable from block %u:\n%s\n",
               locktime + 1, refund);
        dogecoin_free(refund);
        rc = 0;
        goto done;
    }
    if (max_s && pc_doge_to_koinu(max_s, &maximum) != PC_OK) {
        fprintf(stderr, "alice: --max is not an amount\n"); goto done;
    }

    /* Bob refuses a payment whose fee no miner would take, and there is no
       route from his reject back to "raise --fee". She cannot size the final
       transaction yet, since the psbt is missing the scriptSig he adds, but
       every payment this channel builds lands near PC_TYPICAL_TX_BYTES, so a
       fee under that floor could not work on any of them. Say so now rather
       than after a round trip. */
    {
        uint64_t floor_fee = pc_min_fee(PC_TYPICAL_TX_BYTES, 0);
        if (fee < floor_fee) {
            char want[32], got[32];
            pc_koinu_to_doge(floor_fee, want, sizeof(want));
            pc_koinu_to_doge(fee, got, sizeof(got));
            fprintf(stderr, "alice: --fee of %s is below the %s a miner needs "
                            "for a payment this size\n", got, want);
            goto done;
        }
    }
    funding_tx = pc_read_hex_arg(ftx_arg);
    if (!funding_tx) { fprintf(stderr, "alice: cannot read --funding-tx\n"); goto done; }

    char host[64] = "127.0.0.1";
    int port = PC_DEFAULT_PORT;
    if (connect_to) {
        port = pc_wire_split(connect_to, host, sizeof(host), PC_DEFAULT_PORT);
        if (port < 0) { fprintf(stderr, "alice: bad --connect\n"); goto done; }
        if (!host[0]) snprintf(host, sizeof(host), "127.0.0.1");
    }
    fd = pc_wire_connect(host, port);
    if (fd < 0) { fprintf(stderr, "alice: cannot reach %s:%d\n", host, port); goto done; }

    pc_envelope out, in;

    /* [1] ask for a channel, [2] take the key he will sign with */
    memset(&out, 0, sizeof(out));
    out.type = PC_MSG_REQUEST;
    snprintf(out.psbt_hex, sizeof(out.psbt_hex), "01");
    if (!pc_wire_send(fd, &out)) { fprintf(stderr, "alice: send failed\n"); goto done; }
    if (pc_wire_recv(fd, &in) != 1 || in.type != PC_MSG_ANNOUNCE) {
        fprintf(stderr, "alice: peer did not announce a key\n"); goto done;
    }
    if (peer && strcmp(in.psbt_hex, peer) != 0) {
        fprintf(stderr, "alice: peer announced a different pubkey, refusing\n");
        goto done;
    }
    /* sixty-six hex characters is not a public key. one that is not a point on
       the curve still builds a fundable p2sh, and nothing can ever spend it. */
    {
        dogecoin_pubkey bp;
        dogecoin_pubkey_init(&bp);
        bp.compressed = true;
        size_t bl = 0;
        if (strlen(in.psbt_hex) != 66) {
            fprintf(stderr, "alice: peer key is not 33 bytes\n"); goto done;
        }
        utils_hex_to_bin(in.psbt_hex, bp.pubkey, 66, &bl);
        if (bl != 33 || !dogecoin_pubkey_is_valid(&bp)) {
            fprintf(stderr, "alice: peer key is not a point on the curve\n");
            goto done;
        }
    }

    r = pc_channel_init(&ch, alice_pub, in.psbt_hex, locktime, chain);
    if (r != PC_OK) { fprintf(stderr, "alice: channel: %s\n", pc_strerror(r)); goto done; }

    /* the funding must be the one this channel was built for */
    char txid[65] = {0};
    int vout = 0;
    uint64_t capacity = 0;
    r = pc_tx_find_channel_output(&ch, funding_tx, txid, &vout, &capacity);
    if (r != PC_OK) {
        fprintf(stderr, "alice: --funding-tx does not pay %s\n", ch.p2sh_address);
        goto done;
    }
    r = pc_channel_set_funding(&ch, txid, vout, capacity);
    if (r != PC_OK) { fprintf(stderr, "alice: funding: %s\n", pc_strerror(r)); goto done; }

    char cap_s[32];
    pc_koinu_to_doge(capacity, cap_s, sizeof(cap_s));
    printf("channel  %s\n", ch.p2sh_address);
    printf("funding  %s:%d worth %s DOGE\n\n", txid, vout, cap_s);
    fflush(stdout);

    /* [3] the opening PSBT, [4] his answer */
    char *open_psbt = NULL;
    r = pc_channel_open_create(&ch, funding_tx, &open_psbt);
    if (r != PC_OK) { fprintf(stderr, "alice: open: %s\n", pc_strerror(r)); goto done; }

    memset(&out, 0, sizeof(out));
    out.type = PC_MSG_OPEN;
    snprintf(out.ref, sizeof(out.ref), "%s", txid);
    out.vout = vout;
    out.to_bob_koinu = locktime;
    snprintf(out.psbt_hex, sizeof(out.psbt_hex), "%s", open_psbt);
    snprintf(out.tx_hex, sizeof(out.tx_hex), "%s", funding_tx);
    dogecoin_free(open_psbt);
    if (!pc_wire_send(fd, &out)) { fprintf(stderr, "alice: send failed\n"); goto done; }

    if (pc_wire_recv(fd, &in) != 1) { fprintf(stderr, "alice: no answer\n"); goto done; }
    if (in.type == PC_MSG_REJECT) {
        fprintf(stderr, "alice: channel refused: %s\n", in.addr); goto done;
    }
    if (in.type != PC_MSG_ACCEPT) { fprintf(stderr, "alice: unexpected answer\n"); goto done; }
    printf("accepted, %" PRIu64 " koinu available\n\n", in.to_bob_koinu);

    /* [5][6] pay what is invoiced, until he stops invoicing */
    uint64_t paid = 0;
    for (;;) {
        int got = pc_wire_recv(fd, &in);
        if (got != 1) break;
        if (in.type == PC_MSG_REJECT) {
            fprintf(stderr, "alice: refused: %s\n", in.addr); goto done;
        }
        if (in.type != PC_MSG_INVOICE) break;

        uint64_t total = in.to_bob_koinu;
        if (total <= paid) { fprintf(stderr, "alice: invoice does not advance\n"); goto done; }
        if (total > maximum) {
            fprintf(stderr, "alice: invoice of %" PRIu64 " is over --max, stopping\n", total);
            break;
        }
        if (fee > ch.capacity_koinu || total > ch.capacity_koinu - fee) {
            fprintf(stderr, "alice: invoice exceeds the channel\n"); goto done;
        }

        /* The startup check is about --fee alone and cannot see this. A late
           payment nearly drains the channel, so her change lands under the soft
           dust limit and dogecoin charges a full soft limit extra for it, or
           under the hard limit where the transaction stops being standard at
           all. Both are properties of this payment rather than of the fee, and
           she knows total and capacity here, so she can tell before she signs
           rather than after Bob refuses. */
        {
            uint64_t change = ch.capacity_koinu - total - fee;
            if (change > 0 && change < PC_HARD_DUST_KOINU) {
                fprintf(stderr, "alice: this would leave %" PRIu64 " koinu change, "
                        "under the dust limit, and no node would relay it\n", change);
                goto done;
            }
            size_t soft = (total < PC_SOFT_DUST_KOINU ? 1u : 0u)
                        + (change > 0 && change < PC_SOFT_DUST_KOINU ? 1u : 0u);
            uint64_t need = pc_min_fee(PC_TYPICAL_TX_BYTES, soft);
            if (fee < need) {
                char want[32];
                pc_koinu_to_doge(need, want, sizeof(want));
                fprintf(stderr, "alice: an output of this payment falls in the dust "
                        "band, which needs a fee of %s; raise --fee\n", want);
                goto done;
            }
        }

        char amt[32];
        pc_koinu_to_doge(total, amt, sizeof(amt));
        printf("invoice  %s DOGE total, to %s\n", amt, in.addr);

        char *psbt = NULL;
        r = pc_payment_create(&ch, funding_tx, wif, alice_addr, in.addr,
                              total, fee, &psbt);
        if (r != PC_OK) { fprintf(stderr, "alice: payment: %s\n", pc_strerror(r)); goto done; }

        memset(&out, 0, sizeof(out));
        out.type = PC_MSG_PAYMENT;
        snprintf(out.ref, sizeof(out.ref), "%s", ch.funding_txid);
        out.to_bob_koinu = total;
        if (strlen(psbt) + 1 > sizeof(out.psbt_hex)) {
            fprintf(stderr, "alice: psbt does not fit an envelope\n");
            dogecoin_free(psbt); goto done;
        }
        snprintf(out.psbt_hex, sizeof(out.psbt_hex), "%s", psbt);
        dogecoin_free(psbt);
        if (!pc_wire_send(fd, &out)) { fprintf(stderr, "alice: send failed\n"); goto done; }

        if (pc_wire_recv(fd, &in) != 1) { fprintf(stderr, "alice: no ack\n"); goto done; }
        if (in.type == PC_MSG_REJECT) {
            fprintf(stderr, "alice: payment refused: %s\n", in.addr); goto done;
        }
        if (in.type != PC_MSG_ACK || in.to_bob_koinu != total) {
            fprintf(stderr, "alice: payment was not acknowledged\n"); goto done;
        }
        paid = total;
        printf("paid     %s DOGE cumulative\n\n", amt);
        fflush(stdout);

        /* He says whether he is invoicing again. Waiting to find out by reading
           would just block until one of us gives up. */
        if (!in.more) break;
    }

    /* [H] */
    if (want_close && paid) {
        memset(&out, 0, sizeof(out));
        out.type = PC_MSG_CLOSE;
        snprintf(out.ref, sizeof(out.ref), "%s", ch.funding_txid);
        out.to_bob_koinu = paid;
        snprintf(out.psbt_hex, sizeof(out.psbt_hex), "01");
        if (!pc_wire_send(fd, &out)) { fprintf(stderr, "alice: send failed\n"); goto done; }
        if (pc_wire_recv(fd, &in) != 1 || in.type != PC_MSG_CLOSE) {
            fprintf(stderr, "alice: peer would not close\n"); goto done;
        }
        printf("closing transaction, either side can broadcast it:\n%s\n", in.psbt_hex);
    }

    rc = 0;
done:
    if (fd >= 0) close(fd);
    free(funding_tx);
    dogecoin_ecc_stop();
    return rc;
}
