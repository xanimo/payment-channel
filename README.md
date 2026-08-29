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
against a tree carrying dogecoinfoundation/libdogecoin#454, #455, #456 and #457,
install it somewhere, and point at it:

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

bob needs alice's pubkey, the locktime, and a funding outpoint he has confirmed
on chain himself. he cannot see the chain from here, so he takes the outpoint on
the command line and takes the payer's word for nothing else. he also has no
height to compare the locktime against, so stop accepting payments and close well
before it: alice can refund once it passes.

    $ bob --wif $BOB_WIF --peer-pubkey $ALICE_PUB --locktime 300000 \
          --funding $TXID:$VOUT --capacity 100.0 --listen 127.0.0.1:9876

alice pays cumulative totals. `--pay 5 --pay 30` means bob ends up holding a
transaction paying him 30, not 35. wait for the funding to confirm before paying:
without segwit the funding txid is malleable, and a payment signed against an
unconfirmed one points at an outpoint that can cease to exist.

    $ alice --wif $ALICE_WIF --peer-pubkey $BOB_PUB --locktime 300000 \
            --funding $TXID:$VOUT --funding-tx @funding.hex --capacity 100.0 \
            --pay 5.0 --pay 12.5 --pay 30.0 --close

both take `--address` to print the channel address to fund, and `--pubkey` to
print their own key. see doc/PROTOCOL.md for the wire format.

## what bob checks

every payment is countersigned and then parsed before it counts. bob's signature
never leaves his process, so assembling the transaction first is free, and it is
the only way to see the outpoint and the amounts: `dogecoin_tx` is opaque in the
published libdogecoin header and no psbt accessor reports an input's prevout or
an output's value, so a receiving party cannot check what it is being paid
through the shipped surface. src/txcheck.c parses the transaction instead.

a payment is money only if it spends the funding outpoint bob confirmed, pays
bob at least what was claimed, spends no more than the capacity, and pays him
strictly more than the previous one.
