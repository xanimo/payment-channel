# fuzzing

two hand-rolled parsers here consume bytes a peer controls, and neither had been
fuzzed. `pc_envelope_decode` reads a line straight off the socket before anything
has decided the peer is honest, and the reader in `src/txcheck.c` walks varints,
script lengths and output counts on a transaction alice supplied. both are the
right call for a fixed shape and both have been read carefully several times
without turning anything up, which is the point: this is the bug class reading
misses.

needs clang for libFuzzer. the harnesses build with address and undefined
behaviour sanitizers on.

    make LIBDOGECOIN=/path/to/staged/install fuzz

give libFuzzer a scratch directory first and the seed corpus second, so it writes
what it discovers to the scratch directory and leaves the seeds alone:

    ./fuzz/fuzz_envelope /tmp/envwork fuzz/corpus/envelope -max_total_time=300
    ./fuzz/fuzz_txcheck  /tmp/txwork  fuzz/corpus/txcheck  -max_total_time=300

passing the seed directory on its own makes libFuzzer write every input it likes
back into it, which is how a four file corpus becomes two hundred.

## leak detection has to be off

LeakSanitizer dies at exit on this setup, after the target has run, which shows
up as a segfault with an empty log and looks exactly like a finding until you
put it under gdb and read `LeakSanitizer has encountered a fatal error`. it is
not one: `Executed ... in 0 ms` appears first. libFuzzer does its own leak
detection anyway.

    export ASAN_OPTIONS=detect_leaks=0

## check coverage, do not trust the run count

a large run count with no crashes says nothing about what was executed. the
first version of `fuzz_txcheck` used a seed captured from an unrelated run, so
it spent 6.2 million executions dying at the txid comparison, which is a 32 byte
equality no mutation reproduces. everything past it never ran.

    clang -std=gnu99 -O1 -g -fsanitize=fuzzer,address \
          -fprofile-instr-generate -fcoverage-mapping \
          -Iinclude -Isrc -I$LIBDOGECOIN/include -o /tmp/cov_txcheck \
          fuzz/fuzz_txcheck.c src/*.c $LIBDOGECOIN/lib/libdogecoin.a \
          -levent -levent_core -levent_extra -levent_pthreads -lpthread -lm

    LLVM_PROFILE_FILE=/tmp/c.profraw /tmp/cov_txcheck /tmp/w fuzz/corpus/txcheck \
        -max_total_time=60
    llvm-profdata merge -sparse /tmp/c.profraw -o /tmp/c.profdata
    llvm-cov report /tmp/cov_txcheck -instr-profile=/tmp/c.profdata \
        -show-functions src/txcheck.c

with the mismatched seed against with the generated one:

    src/txcheck.c   48.83% regions, 4 of 14 functions never executed
    src/txcheck.c   88.01% regions, 0 of 14 functions never executed

    verify_sigs      0.00%  ->  covered
    rd_push          0.00%  ->  covered

`verify_sigs` is the newest and most intricate byte walking in the file, and it
was the whole reason for writing the harness. `-print_final_stats=1` showing
`ft:` plateauing early is the cheaper version of the same signal.

## the seed has to match the harness

`fuzz/mkseed` builds a channel, funds it, makes a payment, countersigns it, and
prints both the transaction and the constants `fuzz_txcheck.c` has to carry for
that transaction to get past the outpoint check. it refuses to print a seed its
own reader will not accept. regenerate both together:

    make LIBDOGECOIN=/path/to/staged/install fuzz/mkseed
    ./fuzz/mkseed

paste the constants into `fuzz_txcheck.c` and the last line into
`fuzz/corpus/txcheck/closing-tx.hex`.

## what they cover

`fuzz_envelope` decodes the input as a line, and re-encodes anything that
decodes. the round trip is the part worth having: a field that decodes but will
not encode is one that drops a peer mid-conversation, which is how the reject
path died twice, once on a space and once on a comma.

`fuzz_txcheck` runs the input as transaction hex through `pc_tx_verify_payment`,
`pc_tx_find_channel_output` and `pc_tx_sighash` against a channel fixed at two
constant pubkeys and a known funding outpoint, so the fuzzer varies the
transaction rather than the channel.

## last run

    fuzz_envelope   26,107,081 runs   no crashes
    fuzz_txcheck     6,910,275 runs   no crashes

the txcheck number is against the generated seed, so it is the first one that
reached verify_sigs at all. the abort() on the envelope round trip never fired.

both under address and undefined behaviour sanitizers.
