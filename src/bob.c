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

/* The merchant. Bob is paid, so Bob is the one who has to be careful.
 *
 * He is told nothing about the channel in advance. Alice asks, he answers with
 * the key he will sign with, and everything else he learns from the opening
 * PSBT and checks for himself: the redeem script names him, the locktime
 * outlasts the work, the funding transaction really pays the channel, and each
 * payment really pays him more than the last. Then he prices the order and
 * invoices for it.
 *
 * The one thing he cannot do from here is see the chain, so the height he
 * measures the locktime against is given to him, and confirming the funding is
 * the operator's job. */

#include "common.h"

#include <ctype.h>
#include <inttypes.h>
#include <unistd.h>

#define MAX_ORDERS 64

static void usage(void)
{
    fprintf(stderr,
      "usage: bob --wif WIF [--listen [HOST:]PORT] [--testnet|--regtest]\n"
      "           [--height N] [--min-slack N] [--price DOGE ...] [--once]\n"
      "       bob --wif WIF --pubkey\n"
      "\n"
      "  --price is what each order costs, charged in the order given.\n"
      "  --height is the current chain height; Bob cannot see the chain and\n"
      "  refuses a channel whose locktime is not --min-slack blocks above it.\n");
}

/* Everything one connection knows. */
typedef struct {
    pc_channel ch;
    char      *best;            /* newest transaction worth broadcasting */
    uint64_t   best_amount;
    uint64_t   owed;            /* cumulative total invoiced so far */
    int        order;
} session;

static int send_reject(int fd, const char *why)
{
    pc_envelope out;
    memset(&out, 0, sizeof(out));
    out.type = PC_MSG_REJECT;
    snprintf(out.addr, sizeof(out.addr), "%s", why);
    snprintf(out.psbt_hex, sizeof(out.psbt_hex), "01");
    fprintf(stderr, "reject: %s\n", why);
    return pc_wire_send(fd, &out);
}

/* [3][4][D] The opening. Bob learns the channel from the PSBT and refuses it
   unless every part of it is one he checked himself. */
static int handle_open(int fd, session *s, const pc_envelope *in,
                       const char *wif, pc_chain chain,
                       const char *bob_pub, uint32_t height, uint32_t slack)
{
    (void)wif;
    dogecoin_psbt *psbt = NULL;
    if (!dogecoin_psbt_from_hex(in->psbt_hex, &psbt) || !psbt)
        return send_reject(fd, "unreadable psbt"), 0;

    unsigned char rbuf[520];
    size_t rlen = 0;
    int ok = dogecoin_psbt_num_inputs(psbt) == 1 &&
             dogecoin_psbt_input_get_redeemscript(psbt, 0, rbuf, sizeof(rbuf), &rlen);
    dogecoin_psbt_free(psbt);
    if (!ok) return send_reject(fd, "no redeem script"), 0;

    char rhex[PC_MAX_SCRIPT_HEX];
    if (rlen * 2 + 1 > sizeof(rhex)) return send_reject(fd, "script too long"), 0;
    utils_bin_to_hex(rbuf, rlen, rhex);

    /* who is this channel between, and until when */
    char alice_pub[PUBKEYHEXLEN], named_bob[PUBKEYHEXLEN];
    uint32_t locktime = 0;
    if (pc_redeem_parse(rhex, alice_pub, named_bob, &locktime) != PC_OK)
        return send_reject(fd, "not a channel script"), 0;
    if (strcmp(named_bob, bob_pub) != 0)
        return send_reject(fd, "script does not name me"), 0;

    pc_result r = pc_channel_init(&s->ch, alice_pub, bob_pub, locktime, chain);
    if (r != PC_OK) return send_reject(fd, "cannot build channel"), 0;

    uint64_t capacity = 0;
    r = pc_channel_open_accept(&s->ch, in->psbt_hex, in->tx_hex,
                               height, slack, &capacity);
    if (r != PC_OK) {
        return send_reject(fd, r == PC_ERR_STATE ? "locktime too near"
                                                 : "funding does not check out"), 0;
    }

    char cap_s[32];
    pc_koinu_to_doge(capacity, cap_s, sizeof(cap_s));
    printf("channel  %s\n", s->ch.p2sh_address);
    printf("funding  %s:%d worth %s DOGE, locktime %u (height %u)\n",
           s->ch.funding_txid, s->ch.funding_vout, cap_s, locktime, height);
    fflush(stdout);

    pc_envelope out;
    memset(&out, 0, sizeof(out));
    out.type = PC_MSG_ACCEPT;
    snprintf(out.ref, sizeof(out.ref), "%s", s->ch.funding_txid);
    out.vout = s->ch.funding_vout;
    out.to_bob_koinu = capacity;
    snprintf(out.psbt_hex, sizeof(out.psbt_hex), "01");
    return pc_wire_send(fd, &out);
}

/* Whether another order is due, and what it would bring the running total to.
   Bob has to answer this before the ack goes out rather than discover it inside
   send_invoice(), so the two share it and cannot disagree. */
static int invoice_due(const session *s, const char **prices, int nprices,
                       uint64_t *total_out)
{
    if (s->order >= nprices) return 0;
    uint64_t amount = 0;
    if (pc_doge_to_koinu(prices[s->order], &amount) != PC_OK) return 0;
    if (s->owed + amount > s->ch.capacity_koinu) return 0;
    if (total_out) *total_out = s->owed + amount;
    return 1;
}

/* [5] Bob prices the next order and asks for the running total. */
static int send_invoice(int fd, session *s, const char *bob_addr,
                        const char **prices, int nprices)
{
    uint64_t total = 0;
    if (!invoice_due(s, prices, nprices, &total)) return 0;
    s->owed = total;
    s->order++;

    pc_envelope out;
    memset(&out, 0, sizeof(out));
    out.type = PC_MSG_INVOICE;
    snprintf(out.ref, sizeof(out.ref), "%s", s->ch.funding_txid);
    out.to_bob_koinu = s->owed;
    snprintf(out.addr, sizeof(out.addr), "%s", bob_addr);
    snprintf(out.psbt_hex, sizeof(out.psbt_hex), "01");
    printf("invoice  order %d, %s DOGE, %" PRIu64 " total\n",
           s->order, prices[s->order - 1], s->owed);
    fflush(stdout);
    return pc_wire_send(fd, &out);
}

/* [6][G] A payment counts only once Bob has read what he signed. */
static int handle_payment(int fd, session *s, const pc_envelope *in,
                          const char *wif, int more_to_come)
{
    if (strcmp(in->ref, s->ch.funding_txid) != 0)
        return send_reject(fd, "wrong funding"), 0;
    if (in->to_bob_koinu != s->owed)
        return send_reject(fd, "not the invoiced amount"), 0;

    /* Sign first, then read it. Bob's signature never leaves this process
       until the transaction checks out, and assembling it is the only way to
       see the outpoint and the amounts. */
    char *raw = NULL;
    pc_result r = pc_payment_countersign(&s->ch, in->psbt_hex, wif, &raw);
    if (r != PC_OK) return send_reject(fd, "will not countersign"), 0;

    r = pc_tx_verify_payment(&s->ch, raw, in->to_bob_koinu);
    if (r != PC_OK) { dogecoin_free(raw); return send_reject(fd, "pays less than it says"), 0; }

    r = pc_payment_accept(&s->ch, in->psbt_hex, in->to_bob_koinu);
    if (r != PC_OK) { dogecoin_free(raw); return send_reject(fd, "does not advance the channel"), 0; }

    if (s->best) dogecoin_free(s->best);
    s->best = raw;
    s->best_amount = in->to_bob_koinu;
    printf("paid     %" PRIu64 " koinu held (%zu byte tx)\n",
           s->best_amount, strlen(s->best) / 2);
    fflush(stdout);

    pc_envelope out;
    memset(&out, 0, sizeof(out));
    out.type = PC_MSG_ACK;
    snprintf(out.ref, sizeof(out.ref), "%s", s->ch.funding_txid);
    out.to_bob_koinu = s->ch.paid_to_bob_koinu;
    /* Only Bob knows the order is finished. Alice reads this to tell a pause
       from an ending, and blocks on recv forever if it is missing. */
    out.more = more_to_come;
    snprintf(out.psbt_hex, sizeof(out.psbt_hex), "01");
    return pc_wire_send(fd, &out);
}

int main(int argc, char **argv)
{
    const char *wif = NULL, *listen_at = NULL;
    const char *prices[MAX_ORDERS];
    int nprices = 0;
    uint32_t height = 0, slack = 100;
    pc_chain chain = PC_CHAIN_MAIN;
    int want_pubkey = 0, once = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : NULL)
        if      (!strcmp(a, "--wif"))       wif = NEXT();
        else if (!strcmp(a, "--listen"))    listen_at = NEXT();
        else if (!strcmp(a, "--height"))    { const char *v = NEXT(); height = v ? (uint32_t)strtoul(v, NULL, 10) : 0; }
        else if (!strcmp(a, "--min-slack")) { const char *v = NEXT(); slack  = v ? (uint32_t)strtoul(v, NULL, 10) : 0; }
        else if (!strcmp(a, "--testnet"))   chain = PC_CHAIN_TEST;
        else if (!strcmp(a, "--regtest"))   chain = PC_CHAIN_REGTEST;
        else if (!strcmp(a, "--pubkey"))    want_pubkey = 1;
        else if (!strcmp(a, "--once"))      once = 1;
        else if (!strcmp(a, "--price")) {
            const char *v = NEXT();
            if (!v || nprices == MAX_ORDERS) { usage(); return 2; }
            prices[nprices++] = v;
        }
        else { usage(); return 2; }
        #undef NEXT
    }
    if (!wif) { usage(); return 2; }

    dogecoin_ecc_start();
    int rc = 1;

    char bob_pub[PUBKEYHEXLEN], bob_addr[P2PKHLEN];
    if (!pc_identity(wif, chain, bob_pub, bob_addr)) {
        fprintf(stderr, "bob: wif would not decode\n");
        goto done;
    }
    if (want_pubkey) { printf("%s\n", bob_pub); rc = 0; goto done; }
    if (nprices == 0) { usage(); goto done; }

    char host[64] = "127.0.0.1";
    int port = PC_DEFAULT_PORT;
    if (listen_at) {
        port = pc_wire_split(listen_at, host, sizeof(host), PC_DEFAULT_PORT);
        if (port < 0) { fprintf(stderr, "bob: bad --listen\n"); goto done; }
        if (!host[0]) snprintf(host, sizeof(host), "127.0.0.1");
    }
    int lfd = pc_wire_listen(host, port);
    if (lfd < 0) { fprintf(stderr, "bob: cannot listen on %s:%d\n", host, port); goto done; }

    printf("paid to  %s\n", bob_addr);
    printf("listening on %s:%d\n\n", host, port);
    fflush(stdout);

    do {
        int fd = pc_wire_accept(lfd);
        if (fd < 0) continue;

        session s;
        memset(&s, 0, sizeof(s));

        pc_envelope in, out;
        int alive = 1, opened = 0;
        while (alive && pc_wire_recv(fd, &in) == 1) {
            switch (in.type) {
            case PC_MSG_REQUEST:                      /* [1][2] */
                memset(&out, 0, sizeof(out));
                out.type = PC_MSG_ANNOUNCE;
                snprintf(out.psbt_hex, sizeof(out.psbt_hex), "%s", bob_pub);
                snprintf(out.addr, sizeof(out.addr), "%s", bob_addr);
                alive = pc_wire_send(fd, &out);
                break;

            case PC_MSG_OPEN:                         /* [3][4] */
                alive = handle_open(fd, &s, &in, wif, chain, bob_pub, height, slack);
                if (alive) {
                    opened = 1;
                    if (!send_invoice(fd, &s, bob_addr, prices, nprices)) {
                        send_reject(fd, "nothing to invoice");
                        alive = 0;
                    }
                }
                break;

            case PC_MSG_PAYMENT: {                    /* [6][G] */
                if (!opened) { alive = send_reject(fd, "no channel"); break; }
                int more = invoice_due(&s, prices, nprices, NULL);
                if (!more && s.order < nprices)
                    fprintf(stderr, "order %d would exceed the channel\n", s.order + 1);
                alive = handle_payment(fd, &s, &in, wif, more);
                /* Not fatal when nothing more is due: Alice still has a close
                   to send, and Bob has the transaction she wants back. */
                if (alive && more)
                    alive = send_invoice(fd, &s, bob_addr, prices, nprices);
                break;
            }

            case PC_MSG_CLOSE:                        /* [H] */
                if (!s.best) { alive = send_reject(fd, "nothing to close on"); break; }
                memset(&out, 0, sizeof(out));
                out.type = PC_MSG_CLOSE;
                snprintf(out.ref, sizeof(out.ref), "%s", s.ch.funding_txid);
                out.to_bob_koinu = s.best_amount;
                snprintf(out.psbt_hex, sizeof(out.psbt_hex), "%s", s.best);
                pc_wire_send(fd, &out);
                printf("closed   at %" PRIu64 " koinu\n", s.best_amount);
                alive = 0;
                break;

            default:
                alive = send_reject(fd, "unexpected message");
                break;
            }
        }

        if (s.best) {
            printf("\nbroadcast this to take the money:\n%s\n\n", s.best);
            fflush(stdout);
            dogecoin_free(s.best);
        }
        close(fd);
    } while (!once);

    close(lfd);
    rc = 0;
done:
    dogecoin_ecc_stop();
    return rc;
}
