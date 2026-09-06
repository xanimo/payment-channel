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

/* The refund's scriptSig walk, on its own so it can be driven with bytes
 * pc_refund_create() would never produce.
 *
 * Inside pc_refund_create() this can only ever see a serialization
 * refund_bytes() just wrote, so every branch that refuses is unreachable from
 * that entry point and the guard is present rather than tested. The threat it
 * exists for is corruption between assembling the scriptSig and returning it,
 * which no input to pc_refund_create() can produce. Taking (buf) and (fn) as
 * arguments is what lets a fuzzer produce it. */

#ifndef PAYMENT_CHANNEL_REFUND_H
#define PAYMENT_CHANNEL_REFUND_H

#include "channel.h"

/* Walk (buf, fn) as a one-input transaction and check its scriptSig is
   <sig> OP_1 <redeem>, minimally pushed, with nothing after it, and that the
   signature it carries verifies against (apub) over (hash).

   Every read is bounded against fn, including the second half of a two-byte
   varint. A 0xfd prefix does imply a scriptSig long enough that a serialization
   from refund_bytes() covers those bytes, but that is an argument about the
   writer, and this is the one place that is not supposed to make it.

   PC_OK, PC_ERR_SCRIPT if the assembly is not what it should be, PC_ERR_KEY if
   the signature does not verify. */
pc_result pc_refund_walk(const unsigned char *buf, size_t fn, size_t sn,
                         const unsigned char *redeem, size_t rlen,
                         const unsigned char apub[33],
                         const unsigned char hash[32]);

#endif /* PAYMENT_CHANNEL_REFUND_H */
