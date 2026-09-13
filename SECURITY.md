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
