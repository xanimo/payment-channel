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

    fuzz_envelope   22,033,724 runs   no crashes
    fuzz_txcheck     6,172,840 runs   no crashes

both under address and undefined behaviour sanitizers.
