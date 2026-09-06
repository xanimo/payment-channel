# libdogecoin patches

this channel does not build against any released libdogecoin. it needs entry
points that are in the tree but not in a release, and two behaviour fixes. the
patches are archived here so the build is reproducible from this repo alone
rather than depending on what upstream does or when.

apply them to `dogecoinfoundation/libdogecoin` at `0.1.5-dev`, commit
`bf3f9df41263a67bf54e6ca6329fa74432c05067`:

    git clone https://github.com/dogecoinfoundation/libdogecoin
    cd libdogecoin
    git checkout bf3f9df4
    git am /path/to/payment-channel/depends/patches/*.patch
    ./autogen.sh && ./configure --prefix=$PWD/../staged && make && make install

then point the channel at it:

    make LIBDOGECOIN=/path/to/staged

## what each one is for

0001 and 0002 give a p2sh address for an arbitrary redeem script, which is how
the channel address is derived at all.

0003 and 0004 make the psbt finalizer and extractor usable on a script no
built-in classifier recognises, and let a consumer read back what it put in.
`OP_IF` does not classify, so without these the cooperative close cannot be
assembled.

0005 declares six symbols that are exported from the archive but were missing
from the installed header. 0006 drops `LIBDOGECOIN_API` from two static inline
helpers, where it was a contradiction: static wins, no symbol is emitted, and a
consumer that declared them would compile and fail to link.

0007 stops `store_raw_transaction` being handed a buffer that every hex
conversion in the library shares. without it `finalize_transaction` returns a
pointer that the next call overwrites, and freeing it aborts.

0009 makes `inLen` an upper bound on `utils_hex_to_bin` rather than a claim
about the string, which is the contract change and is larger than the diff. it
ran `inLen / 2` iterations without consulting the NUL, left a non-hex nibble as
the zero it was pre-set to, and assigned `*outLen` to `inLen / 2` at the end
regardless, so an empty string with `inLen` 8 returned four bytes off the stack
and reported four bytes written. every caller checking the out-count against the
length it asked for was comparing that length to itself, across 191 call sites.
two of those pass NULL for the count and both are in `test/utils_tests.c`, so
nothing in the library declines it.

this channel does not need it: `src/hex.h` converts strictly and the suite is
green against a dependency with or without 0009, which is what `test_channel`
now asserts. it is here because the reproducer belongs next to the fix.

0008 makes `chain_from_b58_prefix` read the version byte instead of the first
character. regtest's 0x6f encodes to 'm' or 'n' and testnet's 0x71 is only ever
'n', so a regtest address in the upper part of the range was read as testnet and
built against the wrong p2pkh prefix. only 0008 is needed for `contrib/regtest.sh`
to pass reliably; without it, it fails for roughly the share of runs whose
generated address begins with 'n'.

## upstream status

0001 through 0007 correspond to libdogecoin #454, #455, #456, #457 and #459, and
0008 to #461. none are merged and none have a timeline. build against a tree
carrying them; nothing here should be written as though they will land.

0009 has not been proposed upstream and no issue has been opened for it.

libdogecoin #460 publishes `dogecoin_tx_sighash` and `dogecoin_pubkey_verify_sig`
through the installed header. it is not in this series and this channel does not
need it: src/txcheck.c computes the digest itself precisely because that
declaration is unreachable from what ships, and it will keep doing so. see the
comment on `sighash_all`.
