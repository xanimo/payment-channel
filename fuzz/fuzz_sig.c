/* pc_sig_is_standard over arbitrary bytes.
 *
 * The predicate is reachable through fuzz_txcheck and fuzz_refund, but only in
 * the topological sense: those feed whole transactions, and a mutator working
 * on one spends essentially all of its budget being refused long before a
 * scriptSig parses, let alone before a signature inside one is read. Random
 * bytes do not begin 30 xx 02.
 *
 * So it gets its own target and its own corpus. The seeds are real koinu
 * signatures plus the edges a mutator is unlikely to reach on its own, which is
 * what makes the mutation productive: every seed is already past the structural
 * checks, so what the fuzzer explores is the part with arithmetic in it. */

#include "channel.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* The caller strips the hashtype byte before this is reached, so the input
       is a bare DER signature. It has no length ceiling of its own here: the
       predicate's own bound is part of what is under test. */
    pc_result r = pc_sig_is_standard(data, size);

    /* What an accept has to satisfy. These are properties, not a second copy of
       the implementation's branches: an oracle written from the function is a
       regression test for whatever the function currently does, and agrees with
       it about its bugs. This one missed a 33-byte S with a nonzero leading
       byte because it asserted every rule the code checked and nothing about
       the thing the code was deciding.
     *
     * The property that matters is the one the code exists to establish:
     * anything accepted is handed to a verifier, so S must be a scalar that
     * fits in 32 bytes and is at or below half the group order. Magnitude, not
     * shape. */
    if (r == PC_OK) {
        if (size < 8 || size > 72) abort();
        if (data[0] != 0x30) abort();
        if (data[1] != size - 2) abort();
        if (data[2] != 0x02) abort();
        size_t lenr = data[3];
        if (lenr == 0 || 4 + lenr + 2 > size) abort();
        if (data[4] & 0x80) abort();
        size_t poss = 4 + lenr;
        if (data[poss] != 0x02) abort();
        size_t lens = data[poss + 1];
        if (lens == 0 || poss + 2 + lens != size) abort();
        if (data[poss + 2] & 0x80) abort();

        /* R and S are both numbers, and both have to be ones that exist. 33
           bytes is only legal as a zero pad; anything wider is above 2^256 and
           is not a scalar at all. */
        if (lenr > 33) abort();
        if (lenr == 33 && data[4] != 0x00) abort();
        if (lens > 33) abort();
        if (lens == 33 && data[poss + 2] != 0x00) abort();

        /* and at or below half the order, compared as the code should, not as
           the code does */
        static const unsigned char HALF_N[32] = {
            0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0x5d,0x57,0x6e,0x73,0x57,0xa4,0x50,0x1d,0xdf,0xe9,0x2f,0x46,0x68,0x1b,0x20,0xa0
        };
        unsigned char s32[32];
        memset(s32, 0, sizeof(s32));
        size_t n = lens == 33 ? 32 : lens, off = lens == 33 ? 1 : 0;
        memcpy(s32 + (32 - n), data + poss + 2 + off, n);
        if (memcmp(s32, HALF_N, 32) > 0) abort();
    }
    return 0;
}
