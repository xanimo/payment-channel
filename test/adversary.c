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

/* An Alice who does not follow the protocol.
 *
 * The library checks are reachable from the unit test, but Bob's refusals live
 * in his dispatch loop and only a peer that misbehaves can reach them. This is
 * that peer. It opens a channel honestly and then does one wrong thing, so what
 * is being tested is Bob's answer rather than his arithmetic. */

#include "common.h"

#include <unistd.h>

static void usage(void)
{
    fprintf(stderr,
      "usage: adversary --wif WIF --peer-pubkey HEX --locktime N\n"
      "                 --funding-tx HEX|@FILE --connect [HOST:]PORT\n"
      "                 --case reopen|payment-before-open\n");
}

int main(int argc, char **argv)
{
    const char *wif = NULL, *peer = NULL, *ftx_arg = NULL;
    const char *connect_to = NULL, *which = NULL;
    uint32_t locktime = 0;
    pc_chain chain = PC_CHAIN_MAIN;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : NULL)
        if      (!strcmp(a, "--wif"))         wif = NEXT();
        else if (!strcmp(a, "--peer-pubkey")) peer = NEXT();
        else if (!strcmp(a, "--funding-tx"))  ftx_arg = NEXT();
        else if (!strcmp(a, "--connect"))     connect_to = NEXT();
        else if (!strcmp(a, "--case"))        which = NEXT();
        else if (!strcmp(a, "--locktime"))    { const char *v = NEXT(); locktime = v ? (uint32_t)strtoul(v, NULL, 10) : 0; }
        else if (!strcmp(a, "--testnet"))     chain = PC_CHAIN_TEST;
        else if (!strcmp(a, "--regtest"))     chain = PC_CHAIN_REGTEST;
        else { usage(); return 2; }
        #undef NEXT
    }
    if (!wif || !peer || !ftx_arg || !which || !locktime) { usage(); return 2; }

    dogecoin_ecc_start();
    int rc = 1, fd = -1;
    char *funding_tx = NULL, *open_psbt = NULL;

    char alice_pub[PUBKEYHEXLEN], alice_addr[P2PKHLEN];
    if (!pc_identity(wif, chain, alice_pub, alice_addr)) goto done;

    funding_tx = pc_read_hex_arg(ftx_arg);
    if (!funding_tx) { fprintf(stderr, "adversary: cannot read --funding-tx\n"); goto done; }

    char host[64] = "127.0.0.1";
    int port = PC_DEFAULT_PORT;
    if (connect_to) {
        port = pc_wire_split(connect_to, host, sizeof(host), PC_DEFAULT_PORT);
        if (port < 0) goto done;
        if (!host[0]) snprintf(host, sizeof(host), "127.0.0.1");
    }
    fd = pc_wire_connect(host, port);
    if (fd < 0) { fprintf(stderr, "adversary: cannot reach %s:%d\n", host, port); goto done; }

    pc_envelope out, in;

    memset(&out, 0, sizeof(out));
    out.type = PC_MSG_REQUEST;
    snprintf(out.psbt_hex, sizeof(out.psbt_hex), "01");
    if (!pc_wire_send(fd, &out)) goto done;
    if (pc_wire_recv(fd, &in) != 1 || in.type != PC_MSG_ANNOUNCE) goto done;

    pc_channel ch;
    if (pc_channel_init(&ch, alice_pub, in.psbt_hex, locktime, chain) != PC_OK) goto done;

    char txid[65] = {0};
    int vout = 0;
    uint64_t capacity = 0;
    if (pc_tx_find_channel_output(&ch, funding_tx, txid, &vout, &capacity) != PC_OK) goto done;
    if (pc_channel_set_funding(&ch, txid, vout, capacity) != PC_OK) goto done;

    /* a payment before any open at all */
    if (!strcmp(which, "payment-before-open")) {
        memset(&out, 0, sizeof(out));
        out.type = PC_MSG_PAYMENT;
        snprintf(out.ref, sizeof(out.ref), "%s", txid);
        out.to_bob_koinu = 1;
        snprintf(out.psbt_hex, sizeof(out.psbt_hex), "70736274ff01");
        if (!pc_wire_send(fd, &out)) goto done;
        if (pc_wire_recv(fd, &in) != 1) { fprintf(stderr, "adversary: no answer\n"); goto done; }
        if (in.type != PC_MSG_REJECT) {
            fprintf(stderr, "adversary: expected a reject, got type %d\n", (int)in.type);
            goto done;
        }
        printf("rejected: %s\n", in.addr);
        rc = 0;
        goto done;
    }

    if (pc_channel_open_create(&ch, funding_tx, &open_psbt) != PC_OK) goto done;

    memset(&out, 0, sizeof(out));
    out.type = PC_MSG_OPEN;
    snprintf(out.ref, sizeof(out.ref), "%s", txid);
    out.vout = vout;
    out.to_bob_koinu = locktime;
    snprintf(out.psbt_hex, sizeof(out.psbt_hex), "%s", open_psbt);
    snprintf(out.tx_hex, sizeof(out.tx_hex), "%s", funding_tx);
    if (!pc_wire_send(fd, &out)) goto done;
    if (pc_wire_recv(fd, &in) != 1 || in.type != PC_MSG_ACCEPT) {
        fprintf(stderr, "adversary: the honest open was not accepted\n");
        goto done;
    }
    /* he invoices straight after accepting */
    if (pc_wire_recv(fd, &in) != 1 || in.type != PC_MSG_INVOICE) {
        fprintf(stderr, "adversary: expected an invoice\n");
        goto done;
    }

    /* the wrong thing: open a second channel on a session that already has one.
       Handling it would reset the funding outpoint and the amount paid while
       the order count and the held transaction survived from the first. */
    if (!strcmp(which, "reopen")) {
        memset(&out, 0, sizeof(out));
        out.type = PC_MSG_OPEN;
        snprintf(out.ref, sizeof(out.ref), "%s", txid);
        out.vout = vout;
        out.to_bob_koinu = locktime;
        snprintf(out.psbt_hex, sizeof(out.psbt_hex), "%s", open_psbt);
        snprintf(out.tx_hex, sizeof(out.tx_hex), "%s", funding_tx);
        if (!pc_wire_send(fd, &out)) goto done;
        if (pc_wire_recv(fd, &in) != 1) { fprintf(stderr, "adversary: no answer\n"); goto done; }
        if (in.type != PC_MSG_REJECT) {
            fprintf(stderr, "adversary: a second open was not refused, got type %d\n",
                    (int)in.type);
            goto done;
        }
        printf("rejected: %s\n", in.addr);
        rc = 0;
        goto done;
    }

    usage();
done:
    if (open_psbt) dogecoin_free(open_psbt);
    free(funding_tx);
    if (fd >= 0) close(fd);
    dogecoin_ecc_stop();
    return rc;
}
