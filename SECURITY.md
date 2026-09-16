# reporting a vulnerability

mail **bluezr@dogecoin.com**. encrypt it if it is sensitive, to

    00D7 BCFF 5778 2D5D 91D6  281A 0DC6 4171 D69D 92F4

which is the key every commit in this repository is signed with. that is the
whole fingerprint rather than the long key id, because a 64 bit id is short
enough to collide on purpose and this is the one place that matters. fetch it
from
a keyserver or from `https://github.com/xanimo.gpg`, and check it against a
clone rather than against this file:

    git log --show-signature -1

a source archive has no git history, so that check only means anything from a
clone.

there is no bounty and no committee. one person reads the mail.

## what is in scope

alice and bob, the library they share, and the wire protocol between them.
anything where bob acks a payment he cannot spend, or alice pays without being
able to recover, or either accepts a transaction no node would mine.

koinu is a separate project and its own report path. so is dogecoin core. if a
finding is really about one of those, say so and it will get there.

## what is already known, and not a finding

these are stated in the README and are the design rather than defects in it.

the wire protocol is plaintext and unauthenticated. anyone on the path reads
every amount, address and txid, and an active attacker can substitute the
pubkey bob announces during the handshake. `--peer-pubkey` pins his key and is
the only defence; terminate tls or a tunnel in front of the listener.

bob cannot see a chain. `--confirm-cmd` is what checks the funding against one,
and `--trust-peer` turns that off deliberately. a bob running with
`--trust-peer` against an untrusted alice is doing what it says on the flag.

**and `--confirm-cmd` is only as good as the backend behind it.** bob gets one
line back, a depth and a value, and he checks both and refuses either missing.
he cannot check that the block those came out of is a block, because he never
sees it. a backend that reports an output which is not in the chain makes bob
open a channel against nothing, invoice, verify every payment correctly, ack,
and ship goods for a funding output that does not exist. at the sweep there is
nothing to broadcast, and the merchant has lost the goods outright.

## a version floor, for the same reason

**koinu v0.2.5 or later**, and the two reasons are different.

v0.2.3 and earlier do not verify that a block's transactions belong to the
header they arrived behind, which is the check the paragraph above says a
backend has to make. without it `--confirm-cmd` is answered by whichever peer
served the block rather than by the chain, and that is the full-loss path: a
funding output that was never mined, goods shipped, nothing to broadcast at the
sweep. that is the one worth upgrading away from.

v0.2.4 fixes it, and also checks the proof of work on the headers `kw outpoint`
syncs, which v0.2.3 did not do on that call. it cannot sync mainnet: an auxpow
parent coinbase carrying a witness hashes wrong, and enough recent mainnet
headers have one that any command checking work stops a few dozen blocks above
the newest anchor. so v0.2.4 is sound and unusable, which is a strange pair and
worth saying rather than rounding to "upgrade".

v0.2.5 is the first release that is both.

this repository's history contains commits pinning v0.2.1 through v0.2.4.
building pc at one of those and pointing it at the koinu it names gets you a
funding check that does not do what this file says it does, or one that does and
cannot reach a chain to do it with. `alice --version` and `bob --version` print
the koinu they were built against, which is the quickest way to tell.

so the backend must verify that the transactions it scans hash to the merkle
root of the header it trusts, and that the header is on the chain with the most
work. an spv client that parses a block body a peer handed it without that
check is not a chain check, it is a peer check wearing one. if you run
`--confirm-cmd` against something you did not write, that is the question to
ask it first. this is stated here because it is the assumption pc cannot
verify and cannot defend against, not because any particular backend is known
to be wrong.

`--sign-cmd` hands a signer any input 0 it is given, which makes it an oracle
for the key. it is used and not trusted, since what comes back is re-verified,
but it has to be reachable only by its own bob.

the channel is unidirectional and single-payer, because dogecoin has no segwit
and the funding txid is malleable. that is the shape of the thing, not a gap.

nobody has run this in production. it is tested, fuzzed, checked against the
chain's own signatures, and deployed nowhere.

## what a good report looks like

the transaction or the bytes, and what you expected instead. `make check` is
253 checks, 17 attacks and 156 external sighash vectors, so a case that gets
past all of it is worth writing down precisely.
