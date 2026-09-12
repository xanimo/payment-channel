/* Runs fuzz_sig's oracle over a corpus without libFuzzer.
 *
 * The fuzzers need clang and libFuzzer and do not build everywhere; this needs
 * neither, so the seeds and their oracle are exercised by `make check` on any
 * machine rather than only in CI. It finds nothing new on its own, which is the
 * fuzzer's job, but it keeps the seeds honest and it is what demonstrates that
 * the oracle catches a regression rather than only agreeing with the code. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv)
{
    int n = 0;
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) { perror(argv[i]); return 1; }
        uint8_t b[512];
        size_t got = fread(b, 1, sizeof(b), f);
        fclose(f);
        LLVMFuzzerTestOneInput(b, got);   /* aborts if the oracle is violated */
        n++;
    }
    printf("  %d signature seeds, oracle held\n", n);
    return 0;
}
