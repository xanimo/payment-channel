# runbook: losing the primary

what to do when the disk holding bob's state dies. `test/failover.sh` runs this
whole procedure on every `make check`, so it is a description of something that
passes rather than a plan.

## what the replica holds

`--replicate-cmd CMD` runs `CMD <state-file>` after each payment and each close
is written and **before** the ack goes back to alice. a non-zero exit fails the
ack, so alice retries and bob has not answered for money only one disk holds.
that ordering is the whole guarantee: the replica is never behind on what bob
owes.

the sweep replicates its own writes too, but best effort, because it broadcasts
first. a briefly unreachable replica there warns `replica not updated` and is
caught up on the next pass rather than holding a transaction back.

what arrives is one file per outpoint, byte for byte what the primary has. no
key ever reaches it. `.lock` files are not replicated and are not wanted; they
belong to whichever machine is running.

## failover

there is no restore step. `pc_state_adopt` rebuilds the channel from the file
alone, so the sweep needs no key, no session and no memory of the channel, and a
replica directory is already a working primary.

stop the old primary first if any part of it is still alive. two bobs writing
one directory is the one thing this does not defend against: the lock is
`flock` on a local file and means nothing between machines or over nfs.

    $ bob --sweep --state /replica --height-file height.txt \
          --broadcast-cmd "kw send --node NODE" --sweep-margin 100

read the `sweep-status` line it prints. `at_risk_koinu` is the money bob is
holding that the chain has not made final, and it should match what the primary
had taken. `broadcast=N` is how many went out.

to serve again rather than only sweep, point a normal bob at the same directory
and give it the key. the key is not in the replica, so it comes from wherever it
came from before:

    $ bob --wif @key --listen 127.0.0.1:9876 --state /replica ...

## what to expect

a channel is retired when the chain shows its outpoint spent, not when a
transaction is sent, so a sweep re-sends on later passes until then. after a
failover that means the promoted replica may broadcast something the old primary
already broadcast. it is the same transaction with the same txid and a node
rejects the duplicate, which is why the sweep treats "no reject" rather than
"accepted" as success.

running the sweep with `--replicate-cmd` again is worth doing straight away. the
promoted directory is the primary now and needs a second place of its own, and
nothing points that out at the time.

if the funding output is already spent by something else, the sweep retires the
channel without sending. that is the honest outcome: alice's refund got there
first, and no state file was going to change it.

## what this does not cover

a corrupted replica rather than a missing primary. every check here assumes the
files are intact, because `--replicate-cmd` is a copy and pc does not checksum
what it wrote. a filesystem that returns bad bytes silently is outside what this
defends against.
