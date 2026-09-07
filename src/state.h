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
 * exclusive lock on that file for its whole life, so a second session on the
 * same outpoint is refused rather than queued behind it: two peers negotiating
 * against one channel at once have no correct interleaving. The write is to a
 * temporary in the same directory, fsynced, then renamed over, so a crash
 * mid-payment leaves the old ratchet rather than half of a new one. */

#ifndef PAYMENT_CHANNEL_STATE_H
#define PAYMENT_CHANNEL_STATE_H

#include "channel.h"

typedef struct {
    int  fd;                    /* holds the lock; -1 when state is off */
    char path[512];
    char tmp[512];
} pc_state;

/* Take the outpoint's lock and load whatever is on disk into (ch).
 *
 * PC_OK with the ratchet loaded, or zeroed when the file is new.
 * PC_ERR_STATE if another session already holds this outpoint.
 * PC_ERR_ARG if the directory is unusable.
 * PC_ERR_SCRIPT if the stored channel is not the one (ch) describes, which is
 * one outpoint being presented under two sets of channel parameters. */
pc_result pc_state_open(pc_state *st, const char *dir, pc_channel *ch);

/* Persist the ratchet and the transaction worth broadcasting. Call before
   acking: an ack is what makes a merchant ship, so it must not be sent against
   a payment that a crash would forget. */
pc_result pc_state_save(pc_state *st, const pc_channel *ch,
                        const char *best_tx_hex);

/* Release the lock. Safe on a struct that was never opened. */
void pc_state_close(pc_state *st);

/* For a Bob running without state: nothing is held, every call is a no-op. */
void pc_state_disable(pc_state *st);

#endif /* PAYMENT_CHANNEL_STATE_H */
