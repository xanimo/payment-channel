# payment-channel

a unidirectional dogecoin payment channel in c, built on libdogecoin. alice
locks coins in a 2-of-2 p2sh output with a timelocked refund branch, then hands
bob a series of partially signed transactions that each pay him more than the
last. bob holds them and broadcasts only the newest. nothing goes on chain
between the funding and the close, so the payments themselves are free and
instant.

this works on a chain without segwit because the channel is one directional.
bob never has a reason to broadcast an old state, since every old state pays him
less, so there is nothing to revoke and no penalty machinery to get wrong. alice
gets her money back through the `OP_CHECKLOCKTIMEVERIFY` branch if bob
disappears.

    OP_IF <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <alice> OP_CHECKSIGVERIFY
    OP_ELSE OP_2 OP_ENDIF <alice> <bob> OP_2 OP_CHECKMULTISIG

the else branch pushes `OP_2` so the cooperative close is a plain 2-of-2. the if
branch gates alice's unilateral refund on the locktime. the scriptsig for the
cooperative spend is assembled by hand, because `OP_IF` means no generic
finalizer can classify the script:

    OP_0 <alice sig> <bob sig> OP_0 <redeem script>

## building

libdogecoin is not yet released with the entry points this uses, so build
against a tree carrying dogecoinfoundation/libdogecoin#454, #455, #456, #457
and #459, install it somewhere, and point at it:

    make LIBDOGECOIN=/path/to/staged/install
    make LIBDOGECOIN=/path/to/staged/install check

`make check` runs the protocol test and then runs alice against bob over a
socket with a locally minted funding transaction. `contrib/regtest.sh` does the
same thing against a real regtest node, including broadcasting the close, which
is the only thing that proves the transactions are actually valid. it passes:
the close confirms and pays bob exactly what he was promised.

pick the chain with `--testnet` or `--regtest`. it is not a boolean because
dogecoin regtest shares testnet's p2sh prefix but not its p2pkh one, 0x6f
against 0x71, so testnet parameters against a regtest node print addresses the
node does not recognise even though the scripts are identical. the same reason
`generatePrivPubKeypair` cannot mint a regtest key: it takes a boolean, and
regtest's 0xef wif prefix is neither of the two it can produce.

## running it

bob is told nothing about the channel. he prices the orders he is willing to
sell and learns the rest from the opening psbt: who the channel is between, what
it is worth, and until when. `--price` is what one order costs, so the three
below invoice cumulative totals of 5, 12.5 and 30.

he cannot see the chain, so the height he measures the locktime against is given
to him, and he refuses a channel whose locktime is not at least `--min-slack`
blocks above it. alice can refund once the locktime passes, so a channel that
expires while bob is holding a payment is one he loses.

    $ bob --wif $BOB_WIF --listen 127.0.0.1:9876 \
          --height 5100000 --min-slack 100 \
          --price 5.0 --price 7.5 --price 17.5

alice prints the address, funds it, then pays what she is invoiced up to
`--max`. wait for the funding to confirm before paying: without segwit the
funding txid is malleable, and a payment signed against an unconfirmed one
points at an outpoint that can cease to exist.

    $ alice --wif $ALICE_WIF --peer-pubkey $BOB_PUB --locktime 5200000 --address
    $ alice --wif $ALICE_WIF --peer-pubkey $BOB_PUB --locktime 5200000 \
            --funding-tx @funding.hex --max 100.0 \
            --connect 127.0.0.1:9876 --close

she is handed the funding transaction rather than an outpoint and works out
which of its outputs pays the channel herself. `--peer-pubkey` pins bob's key;
without it she trusts whatever he announces, and the transport is plain tcp in
the clear. both take `--pubkey` to print their own key. see doc/PROTOCOL.md for
the wire format.

## what bob checks

at the opening he checks that the redeem script names his own key, that the
transaction travelling beside the psbt really pays that script, and that the
locktime clears the height he was given by `--min-slack`. the capacity is what
he reads off the funding output, not what he is told it is worth.

every payment is countersigned and then parsed before it counts. bob's signature
never leaves his process, so assembling the transaction first is free, and it is
the only way to see the outpoint and the amounts: `dogecoin_tx` is opaque in the
published libdogecoin header and no psbt accessor reports an input's prevout or
an output's value, so a receiving party cannot check what it is being paid
through the shipped surface. src/txcheck.c parses the transaction instead.

a payment is money only if it spends the funding outpoint bob confirmed, pays
bob at least what was claimed, spends no more than the capacity, and pays him
strictly more than the previous one.
