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

    /* The one invariant worth asserting: a signature this calls standard has to
       have the shape it just claimed to check. Anything it accepts is handed
       straight to a verifier, so an accept that does not satisfy these is the
       bug, not a crash. */
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
    }
    return 0;
}
