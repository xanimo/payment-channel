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

/* One funding outpoint, one channel, for as long as that outpoint exists.
 *
 * Bob serves each connection in a forked child, so the ratchet in a session
 * struct starts at zero every time. Three sessions naming one funding output
 * each acked a payment of five DOGE and each got goods shipped, while only one
 * of the three transactions can ever confirm. The ratchet has to outlive the
 * connection, and the process, or a merchant ships repeatedly for one payment.
 *
 * State is a directory, one file per outpoint, named for it. A session takes an
 * exclusive lock for its whole life, so a second session on the same outpoint
 * is refused rather than queued behind it: two peers negotiating against one
 * channel at once have no correct interleaving. The write is to a temporary in
 * the same directory, fsynced, then renamed over, so a crash mid-payment leaves
 * the old ratchet rather than half of a new one.
 *
 * The lock is a separate file, and that is not tidiness. flock attaches to an
 * open file description, which names an inode rather than a path, so renaming
 * the data file over itself leaves the holder locking an unlinked inode while
 * the next process locks the new one and sees no contention. The lock excluded
 * correctly until the first payment was recorded and then stopped excluding at
 * all, which is the opposite of the case worth defending. The lock file is
 * created once and never replaced.
 *
 * Nothing is ever deleted. A closed channel is marked, not removed, because
 * unlinking a lock file races with the next process creating one at the same
 * path and both would then believe they hold it. */

#ifndef PAYMENT_CHANNEL_STATE_H
#define PAYMENT_CHANNEL_STATE_H

#include "channel.h"

typedef struct {
    int  lock_fd;               /* holds the lock; -1 when state is off */
    char path[512];
    char tmp[512];
    char lock[512];
} pc_state;

/* Take the outpoint's lock and load whatever is on disk into (ch).
 *
 * PC_OK with the ratchet loaded, or zeroed when the file is new.
 * PC_ERR_STATE if another session already holds this outpoint.
 * PC_ERR_ARG if the directory is unusable.
 * PC_ERR_SCRIPT if the stored channel is not the one (ch) describes, which is
 * one outpoint being presented under two sets of channel parameters.
 * PC_ERR_CLOSED if this outpoint has already been closed. */
pc_result pc_state_open(pc_state *st, const char *dir, pc_channel *ch);

/* Persist the ratchet and the transaction worth broadcasting. Call before
   acking: an ack is what makes a merchant ship, so it must not be sent against
   a payment that a crash would forget. */
pc_result pc_state_save(pc_state *st, const pc_channel *ch,
                        const char *best_tx_hex);

/* Mark the channel finished. A cooperative close is the last thing that happens
   on an outpoint, so a later session naming it is asking to be shipped against
   a transaction this one intends to broadcast. Call before answering the close,
   for the same reason saving comes before the ack. */
pc_result pc_state_retire(pc_state *st, const pc_channel *ch,
                          const char *best_tx_hex);

/* Note that the transaction has been handed to a node, without closing the
   channel. p2p has no positive acknowledgement, so a send that drew no reject
   is not a send that confirmed: the peer may never relay it and a mempool may
   drop it later. Retiring on that would leave a channel finished on Bob's side
   and unspent on the chain, and nothing sweeps a retired channel again. */
pc_result pc_state_mark_sent(pc_state *st, const pc_channel *ch,
                             const char *best_tx_hex);

/* Read a state file without a channel to check it against.
 *
 * pc_state_open() validates what is on disk against a channel the caller
 * already built from an opening PSBT. A sweep has no such channel: the outpoint
 * is the filename and everything else has to come out of the file. This takes
 * the same lock, so a channel a live session is holding is skipped rather than
 * swept out from under it, and fills (ch) and (tx) from what it finds.
 *
 * PC_OK, PC_ERR_STATE if a session holds it, PC_ERR_ARG if the file is not one
 * of ours or (txcap) is too small for the transaction it carries. */
pc_result pc_state_adopt(pc_state *st, const char *dir,
                         const char *txid_hex, int vout,
                         pc_channel *ch, char *tx, size_t txcap,
                         int *closed, int *sent);

/* Release the lock. Safe on a struct that was never opened. */
void pc_state_close(pc_state *st);

/* For a Bob running without state: nothing is held, every call is a no-op. */
void pc_state_disable(pc_state *st);

#endif /* PAYMENT_CHANNEL_STATE_H */
