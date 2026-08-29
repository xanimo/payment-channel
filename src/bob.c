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

/* The receiving side. Bob is paid, so Bob is the one who has to be careful.
 *
 * He never takes the payer's word for anything he can check himself: the peer
 * pubkey is pinned on the command line, the funding outpoint and capacity are
 * ones he confirmed on chain before starting, and every payment is countersigned
 * and then parsed before it is treated as money. Each accepted payment replaces
 * the last, and only the newest one is worth broadcasting. */

#include "common.h"

#include <ctype.h>
#include <inttypes.h>
#include <unistd.h>

static void usage(void)
{
    fprintf(stderr,
      "usage: bob --wif WIF --peer-pubkey HEX --locktime N\n"
      "           --funding TXID:VOUT --capacity DOGE\n"
      "           [--listen [HOST:]PORT] [--testnet] [--once]\n"
      "       bob --wif WIF --pubkey\n"
      "       bob --wif WIF --peer-pubkey HEX --locktime N --address\n"
      "\n"
      "  --funding and --capacity must describe a funding output you have\n"
      "  already confirmed on chain. Bob cannot see the chain from here.\n");
}

int main(int argc, char **argv)
{
    const char *wif = NULL, *peer = NULL, *funding = NULL, *cap_s = NULL;
    const char *listen_at = NULL;
    uint32_t locktime = 0;
    int testnet = 0, want_pubkey = 0, want_address = 0, once = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : NULL)
        if      (!strcmp(a, "--wif"))         wif = NEXT();
        else if (!strcmp(a, "--peer-pubkey")) peer = NEXT();
        else if (!strcmp(a, "--funding"))     funding = NEXT();
        else if (!strcmp(a, "--capacity"))    cap_s = NEXT();
        else if (!strcmp(a, "--listen"))      listen_at = NEXT();
        else if (!strcmp(a, "--locktime"))    { const char *v = NEXT(); locktime = v ? (uint32_t)strtoul(v, NULL, 10) : 0; }
        else if (!strcmp(a, "--testnet"))     testnet = 1;
        else if (!strcmp(a, "--pubkey"))      want_pubkey = 1;
        else if (!strcmp(a, "--address"))     want_address = 1;
        else if (!strcmp(a, "--once"))        once = 1;
        else { usage(); return 2; }
        #undef NEXT
    }
    if (!wif) { usage(); return 2; }

    dogecoin_ecc_start();
    int rc = 1;

    char bob_pub[PUBKEYHEXLEN], bob_addr[P2PKHLEN];
    if (!pc_identity(wif, testnet, bob_pub, bob_addr)) {
        fprintf(stderr, "bob: wif would not decode\n");
        goto done;
    }
    if (want_pubkey) { printf("%s\n", bob_pub); rc = 0; goto done; }

    if (!peer || !locktime) { usage(); goto done; }

    pc_channel ch;
    pc_result r = pc_channel_init(&ch, peer, bob_pub, locktime, testnet);
    if (r != PC_OK) {
        fprintf(stderr, "bob: channel: %s\n", pc_strerror(r));
        goto done;
    }
    if (want_address) { printf("%s\n", ch.p2sh_address); rc = 0; goto done; }

    if (!funding || !cap_s) { usage(); goto done; }

    char txid[65];
    int vout = 0;
    if (!pc_split_outpoint(funding, txid, &vout)) {
        fprintf(stderr, "bob: --funding wants TXID:VOUT\n");
        goto done;
    }
    uint64_t capacity = 0;
    if (pc_doge_to_koinu(cap_s, &capacity) != PC_OK) {
        fprintf(stderr, "bob: --capacity is not an amount\n");
        goto done;
    }
    r = pc_channel_set_funding(&ch, txid, vout, capacity);
    if (r != PC_OK) {
        fprintf(stderr, "bob: funding: %s\n", pc_strerror(r));
        goto done;
    }

    char host[64] = "127.0.0.1";
    int port = PC_DEFAULT_PORT;
    if (listen_at) {
        port = pc_wire_split(listen_at, host, sizeof(host), PC_DEFAULT_PORT);
        if (port < 0) { fprintf(stderr, "bob: bad --listen\n"); goto done; }
        if (!host[0]) snprintf(host, sizeof(host), "127.0.0.1");
    }

    int lfd = pc_wire_listen(host, port);
    if (lfd < 0) { fprintf(stderr, "bob: cannot listen on %s:%d\n", host, port); goto done; }

    printf("channel  %s\n", ch.p2sh_address);
    printf("paid to  %s\n", bob_addr);
    printf("funding  %s:%d, %s DOGE\n", ch.funding_txid, ch.funding_vout, cap_s);
    printf("listening on %s:%d\n\n", host, port);
    fflush(stdout);

    do {
        int fd = pc_wire_accept(lfd);
        if (fd < 0) continue;

        char *best = NULL;                 /* newest transaction worth having */
        uint64_t best_amount = 0;
        ch.paid_to_bob_koinu = 0;

        pc_envelope in, out;
        int alive = pc_wire_recv(fd, &in) == 1 && in.type == PC_MSG_ANNOUNCE;
        if (alive && strcmp(in.psbt_hex, ch.alice_pubkey_hex) != 0) {
            fprintf(stderr, "peer announced a pubkey that is not the pinned one\n");
            alive = 0;
        }
        if (alive && in.to_bob_koinu != (uint64_t)locktime) {
            fprintf(stderr, "peer announced locktime %" PRIu64 ", expected %u\n",
                    in.to_bob_koinu, locktime);
            alive = 0;
        }
        if (alive) {
            pc_announce(&out, bob_pub, locktime);
            alive = pc_wire_send(fd, &out);
        }

        while (alive) {
            int got = pc_wire_recv(fd, &in);
            if (got != 1) break;

            if (in.type == PC_MSG_CLOSE) {
                if (!best) { fprintf(stderr, "close with nothing to close on\n"); break; }
                memset(&out, 0, sizeof(out));
                out.type = PC_MSG_CLOSE;
                snprintf(out.ref, sizeof(out.ref), "%s", ch.funding_txid);
                out.to_bob_koinu = best_amount;
                snprintf(out.psbt_hex, sizeof(out.psbt_hex), "%s", best);
                pc_wire_send(fd, &out);
                printf("closed at %" PRIu64 " koinu\n", best_amount);
                break;
            }
            if (in.type != PC_MSG_PAYMENT) { fprintf(stderr, "unexpected message\n"); break; }
            if (strcmp(in.ref, ch.funding_txid) != 0) {
                fprintf(stderr, "payment references another funding tx\n");
                break;
            }

            /* Sign first, then read what was signed. Bob's signature never
               leaves this process until the transaction checks out, so there is
               nothing to lose by assembling it before judging it, and this is
               the only way to see the outpoint and the amounts. */
            char *raw = NULL;
            r = pc_payment_countersign(&ch, in.psbt_hex, wif, &raw);
            if (r != PC_OK) {
                fprintf(stderr, "countersign: %s\n", pc_strerror(r));
                break;
            }
            r = pc_tx_verify_payment(&ch, raw, bob_addr, in.to_bob_koinu);
            if (r != PC_OK) {
                fprintf(stderr, "payment does not say what it claims: %s\n", pc_strerror(r));
                dogecoin_free(raw);
                break;
            }
            r = pc_payment_accept(&ch, in.psbt_hex, in.to_bob_koinu);
            if (r != PC_OK) {
                fprintf(stderr, "reject: %s\n", pc_strerror(r));
                dogecoin_free(raw);
                break;
            }

            if (best) dogecoin_free(best);
            best = raw;
            best_amount = in.to_bob_koinu;
            printf("accepted %" PRIu64 " koinu (%zu byte tx held)\n",
                   best_amount, strlen(best) / 2);
            fflush(stdout);

            memset(&out, 0, sizeof(out));
            out.type = PC_MSG_ACK;
            snprintf(out.ref, sizeof(out.ref), "%s", ch.funding_txid);
            out.to_bob_koinu = ch.paid_to_bob_koinu;
            snprintf(out.psbt_hex, sizeof(out.psbt_hex), "01");
            alive = pc_wire_send(fd, &out);
        }

        if (best) {
            printf("\nbroadcast this to take the money:\n%s\n\n", best);
            fflush(stdout);
            dogecoin_free(best);
        }
        close(fd);
    } while (!once);

    close(lfd);
    rc = 0;
done:
    dogecoin_ecc_stop();
    return rc;
}
