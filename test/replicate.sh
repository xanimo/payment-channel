#!/usr/bin/env bash
# A payment reaches a second place before Bob acks it, so a disk that dies
# between the payment and the sweep is not a lost payment. --replicate-cmd is run
# as CMD <state-file> after each save and before the ack; a non-zero exit fails
# the ack to a retry rather than answering for a payment only one disk holds.
set -eu

cd "$(dirname "$0")/.."
PORT=${PORT:-19895}
LOCKTIME=${LOCKTIME:-300000}
for b in alice bob test/mkfunding; do
    [ -x "$b" ] || { echo "build first: make check" >&2; exit 1; }
done

WORK=$(mktemp -d)
BOB_PID=
trap 'rm -rf "$WORK"; [ -n "$BOB_PID" ] && kill "$BOB_PID" 2>/dev/null || true' EXIT
mkdir -p "$WORK/state" "$WORK/mirror"

read -r ALICE_WIF ALICE_ADDR < <(./test/mkfunding --keys)
read -r BOB_WIF   _          < <(./test/mkfunding --keys)
BOB_PUB=$(./bob --wif "$BOB_WIF" --pubkey)
CHANNEL=$(./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" --address)
read -r FUNDING_HEX _ _ < <(./test/mkfunding "$CHANNEL" "$ALICE_ADDR" 100.0)
printf '%s' "$FUNDING_HEX" > "$WORK/funding.hex"

fail=0
say() { printf "  %-52s %s\n" "$1" "$2"; }

run_alice() {
    ./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
            --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$1" \
            --max 5.0 > "$WORK/alice.log" 2>&1 || true
}

echo "a payment is durable in a second place before the ack:"

# a replica that succeeds: the state file is mirrored and the payment is acked
./bob --wif "$BOB_WIF" --listen "127.0.0.1:$PORT" --trust-peer --once --height 1000 \
      --min-slack 100 --state "$WORK/state" --price 5.0 \
      --replicate-cmd "cp -t $WORK/mirror" > "$WORK/bob.log" 2>&1 &
BOB_PID=$!
for _ in $(seq 1 100); do grep -q listening "$WORK/bob.log" 2>/dev/null && break; sleep 0.1; done
run_alice "$PORT"
wait "$BOB_PID" 2>/dev/null || true; BOB_PID=

grep -q "koinu held" "$WORK/bob.log" \
    && say "the payment is acked" "yes" \
    || { say "the payment is acked" "no"; fail=1; }
ls "$WORK/mirror"/*.channel >/dev/null 2>&1 \
    && say "and the state reached the replica" "yes" \
    || { say "and the state reached the replica" "no"; fail=1; }
# what the replica holds matches the live state, so a failover sees the payment
if [ -f "$WORK/state"/*.channel ] && diff -q "$WORK"/state/*.channel "$WORK"/mirror/*.channel >/dev/null; then
    say "the replica matches the live ratchet" "yes"
else
    say "the replica matches the live ratchet" "no"; fail=1
fi

# a replica that fails: the payment is refused, not acked against one disk
rm -rf "$WORK/state2"; mkdir -p "$WORK/state2"
./bob --wif "$BOB_WIF" --listen "127.0.0.1:$((PORT+1))" --trust-peer --once --height 1000 \
      --min-slack 100 --state "$WORK/state2" --price 5.0 \
      --replicate-cmd "false" > "$WORK/bob2.log" 2>&1 &
BOB_PID=$!
for _ in $(seq 1 100); do grep -q listening "$WORK/bob2.log" 2>/dev/null && break; sleep 0.1; done
run_alice "$((PORT+1))"
wait "$BOB_PID" 2>/dev/null || true; BOB_PID=

grep -q "cannot replicate" "$WORK/alice.log" \
    && say "a failed replica refuses the payment" "yes" \
    || { say "a failed replica refuses the payment" "$(tail -1 "$WORK/alice.log")"; fail=1; }
grep -q "koinu held" "$WORK/bob2.log" \
    && { say "and nothing is acked against one disk" "acked anyway"; fail=1; } \
    || say "and nothing is acked against one disk" "yes"

# the sweep replicates its own writes too. the paid channel from the first run
# is still in state; sweep it due (huge margin) with a broadcast stub and no
# confirm backend, so it broadcasts and retires, and check the replica updated.
mkdir -p "$WORK/mirror2"
printf '#!/usr/bin/env bash\nread -r _\necho sent\n' > "$WORK/send"; chmod +x "$WORK/send"
printf '1000\n' > "$WORK/height"
./bob --sweep --state "$WORK/state" --height-file "$WORK/height" \
      --broadcast-cmd "$WORK/send" --sweep-margin 400000 \
      --replicate-cmd "cp -t $WORK/mirror2" --metrics-file "$WORK/metrics" \
      > "$WORK/sweep.log" 2>&1 || true
if grep -q "1 broadcast" "$WORK/sweep.log" && ls "$WORK/mirror2"/*.channel >/dev/null 2>&1; then
    say "the sweep replicates its own writes" "yes"
else
    say "the sweep replicates its own writes" "$(tail -1 "$WORK/sweep.log")"; fail=1
fi
# observability: the status line carries replica health and the metrics file is
# a scrapable snapshot a monitor reads
grep -q "replica=ok" "$WORK/sweep.log" \
    && say "the status line reports replica health" "yes" \
    || { say "the status line reports replica health" "$(grep sweep-status "$WORK/sweep.log")"; fail=1; }
if grep -q "^pc_sweep_broadcast 1" "$WORK/metrics" \
   && grep -q "^pc_sweep_replica_stale 0" "$WORK/metrics"; then
    say "the metrics file is a scrapable snapshot" "yes"
else
    say "the metrics file is a scrapable snapshot" "no"; fail=1
fi

# a replica that fails mid-sweep shows stale in the status and metrics, best
# effort, without stopping the broadcast
rm -rf "$WORK/state3"; mkdir -p "$WORK/state3"
cp "$WORK"/state/*.channel "$WORK/state3"/ 2>/dev/null || true
./bob --sweep --state "$WORK/state3" --height-file "$WORK/height" \
      --broadcast-cmd "$WORK/send" --sweep-margin 400000 \
      --replicate-cmd "false" --metrics-file "$WORK/metrics3" \
      > "$WORK/sweep3.log" 2>&1 || true
if [ -s "$WORK/state3"/*.channel ] 2>/dev/null; then
    grep -q "replica=stale" "$WORK/sweep3.log" && grep -q "^pc_sweep_replica_stale 1" "$WORK/metrics3" \
        && say "a lagging replica reads stale, sweep still runs" "yes" \
        || { say "a lagging replica reads stale, sweep still runs" "no"; fail=1; }
fi

[ "$fail" = 0 ] || { echo "replicate FAILED" >&2; exit 1; }
echo "replicate ok"
