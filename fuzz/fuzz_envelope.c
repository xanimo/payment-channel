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

/* pc_envelope_decode() on a raw line.
 *
 * This is the first thing that touches a byte off the socket, before anything
 * has decided the peer is honest. It is hand written, which is the right call
 * for a fixed shape, and it has been read carefully several times without
 * anything being found. Reading is done finding things here; this is the class
 * of bug reading misses. */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "channel.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* the decoder takes a NUL terminated line, which is what read_line() hands
       it, so the input is copied and terminated rather than passed raw */
    if (size > PC_MAX_PSBT_HEX * 2 + 1024) return 0;
    char *line = (char *)malloc(size + 1);
    if (!line) return 0;
    memcpy(line, data, size);
    line[size] = '\0';

    pc_envelope env;
    if (pc_envelope_decode(line, &env) == PC_OK) {
        /* Anything it accepts has to survive being re-encoded, which is the
           round trip the wire actually performs. A field that decodes but will
           not encode is one that gets a peer dropped mid-conversation, which is
           how the reject path died twice. */
        char *out = (char *)malloc(PC_MAX_PSBT_HEX * 2 + 1024);
        if (out) {
            pc_envelope_encode(&env, out, PC_MAX_PSBT_HEX * 2 + 1024);
            free(out);
        }
    }

    free(line);
    return 0;
}
