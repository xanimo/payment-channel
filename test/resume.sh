#!/usr/bin/env bash
# One funding outpoint is one channel, across connections and across restarts.
#
# Bob serves each connection in a forked child, so before --state the ratchet in
# a session struct started at zero every time. Three sessions naming one funding
# output each acked five DOGE and each got goods, while only one of those three
# transactions can ever confirm: the merchant ships three times and banks once.
#
# What this pins: the ratchet survives the connection, it survives the process,
# invoices carry on from it rather than restarting, two sessions cannot hold one
# outpoint at once, and a long-lived Bob refuses to run without somewhere to
# keep it.
set -eu

cd "$(dirname "$0")/.."
PORT=${PORT:-19884}
LOCKTIME=${LOCKTIME:-300000}

for b in alice bob test/mkfunding; do
    [ -x "$b" ] || { echo "build first: make check" >&2; exit 1; }
done

WORK=$(mktemp -d)
BOB_PID=
trap 'rm -rf "$WORK"; [ -n "$BOB_PID" ] && kill "$BOB_PID" 2>/dev/null || true' EXIT
mkdir -p "$WORK/state"
printf '1000\n' > "$WORK/height"

read -r ALICE_WIF ALICE_ADDR < <(./test/mkfunding --keys)
read -r BOB_WIF   _          < <(./test/mkfunding --keys)
BOB_PUB=$(./bob --wif "$BOB_WIF" --pubkey)
CHANNEL=$(./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" \
                  --locktime "$LOCKTIME" --address)
read -r FUNDING_HEX _ _ < <(./test/mkfunding "$CHANNEL" "$ALICE_ADDR" 100.0)
printf '%s' "$FUNDING_HEX" > "$WORK/funding.hex"

start_bob() {
    ./bob --wif "$BOB_WIF" --listen "127.0.0.1:$PORT" \
          --min-slack 100 --height-file "$WORK/height" \
          --state "$WORK/state" \
          --price 5.0 >> "$WORK/bob.log" 2>&1 &
    BOB_PID=$!
    for _ in $(seq 1 100); do
        grep -q "listening" "$WORK/bob.log" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "FAIL: bob never listened" >&2; exit 1
}
stop_bob() {
    [ -n "$BOB_PID" ] || return 0
    kill "$BOB_PID" 2>/dev/null || true
    wait "$BOB_PID" 2>/dev/null || true
    BOB_PID=
}
# A purchase that leaves the channel open. --close is deliberately absent:
# closing retires the outpoint, which is its own property tested at the end.
buy() {
    before=$(paid_on_disk 2>/dev/null || echo 0)
    ./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
            --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$PORT" \
            --max 100.0 > "$WORK/alice-$1.log" 2>&1 || true
    after=$(paid_on_disk 2>/dev/null || echo 0)
    [ "${after:-0}" -gt "${before:-0}" ] && echo YES || echo no
}
close_channel() {
    ./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
            --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$PORT" \
            --max 100.0 --close > "$WORK/alice-$1.log" 2>&1 || true
    grep -qi "closing transaction" "$WORK/alice-$1.log" && echo YES || echo no
}
paid_on_disk() { awk '/^paid /{print $2}' "$WORK"/state/*.channel; }

fail=0
say() { printf "  %-52s %s\n" "$1" "$2"; }

echo "one outpoint, many connections:"

# a long-lived Bob with nowhere to keep the ratchet refuses to start at all
if ./bob --wif "$BOB_WIF" --listen "127.0.0.1:$PORT" \
         --height-file "$WORK/height" --price 5.0 >"$WORK/nostate.log" 2>&1; then
    say "refuses to run long-lived without --state" "NO, it started"; fail=1
else
    grep -q "state DIR is required" "$WORK/nostate.log" \
        && say "refuses to run long-lived without --state" "yes" \
        || { say "refuses to run long-lived without --state" "wrong reason"; fail=1; }
fi

start_bob
for i in 1 2 3; do
    got=$(buy "$i")
    [ "$got" = YES ] || { say "session $i completes" "no"; fail=1; }
done
say "three sessions on one outpoint all complete" "yes"

# the ratchet is cumulative, so three purchases at 5.0 is 15.0 held, not 5.0
after_three=$(paid_on_disk)
[ "$after_three" = 1500000000 ] \
    && say "and the total is cumulative, not replayed" "$after_three koinu" \
    || { say "and the total is cumulative, not replayed" "$after_three, wanted 1500000000"; fail=1; }

# A second session cannot hold the outpoint while another has it. Driving this
# with two alices does not test it: the first completes and releases the lock
# before the second connects. The lock is taken directly instead, which is what
# a concurrent child would be holding.
#
# It is taken on the .lock file, and that is the whole point of there being one.
# When this locked the data file it passed for the wrong reason: a save renames
# a new inode over that path, so the holder is left locking an unlinked inode
# and the next process locks the new one unopposed. Locking the data file here
# now reports "not refused", which is what the code did before the split.
python3 - "$WORK"/state/*.channel.lock <<'LOCK' &
import fcntl, sys, time
f = open(sys.argv[1], "r+")
fcntl.flock(f, fcntl.LOCK_EX)
print("held", flush=True)
time.sleep(8)
LOCK
HOLD=$!
sleep 1
buy concurrent > /dev/null
if grep -qi "in use" "$WORK/alice-concurrent.log"; then
    say "a second session on a held outpoint is refused" "yes"
else
    say "a second session on a held outpoint is refused" "not refused"; fail=1
fi
kill "$HOLD" 2>/dev/null || true
wait "$HOLD" 2>/dev/null || true

# and it survives the process, which is the whole point
stop_bob
was=$(paid_on_disk)
start_bob
got=$(buy afterrestart)
now=$(paid_on_disk)
[ "$got" = YES ] && [ "$now" -gt "$was" ] \
    && say "survives a restart and carries on from $was" "$now koinu" \
    || { say "survives a restart" "got=$got was=$was now=$now"; fail=1; }

# closing is the end of the outpoint, not a pause in it. anything after it is
# asking to be shipped against the transaction this close hands over.
[ "$(close_channel closing)" = YES ] \
    && say "a close hands over the transaction" "yes" \
    || { say "a close hands over the transaction" "no"; fail=1; }
grep -q "^closed 1" "$WORK"/state/*.channel \
    && say "and marks the outpoint closed on disk" "yes" \
    || { say "and marks the outpoint closed on disk" "no"; fail=1; }
buy afterclose > /dev/null
if grep -qi "was closed" "$WORK/alice-afterclose.log"; then
    say "a session after the close is refused" "yes"
else
    say "a session after the close is refused" "accepted"; fail=1
fi
stop_bob

[ "$fail" = 0 ] || { echo "resume FAILED" >&2; exit 1; }
echo "resume ok"
