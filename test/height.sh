#!/usr/bin/env bash
# The height is re-read for every channel, not once at startup.
#
# --min-slack is checked against the height at open. A number given on the
# command line is correct once, so a Bob running for a day compares locktimes to
# a height a day old and the margin he thinks he has erodes silently. A channel
# whose locktime has already passed still looks like it has room, and Alice's
# refund is spendable the moment that is true.
#
# What this pins: one Bob process gives different answers for the same channel
# as the height under it moves, and stops answering at all when nothing is
# keeping the file up to date.
set -eu

cd "$(dirname "$0")/.."
PORT=${PORT:-19886}
LOCKTIME=${LOCKTIME:-300000}

for b in alice bob test/mkfunding; do
    [ -x "$b" ] || { echo "build first: make check" >&2; exit 1; }
done

WORK=$(mktemp -d)
BOB_PID=
trap 'rm -rf "$WORK"; [ -n "$BOB_PID" ] && kill "$BOB_PID" 2>/dev/null || true' EXIT
mkdir -p "$WORK/state"

read -r ALICE_WIF ALICE_ADDR < <(./test/mkfunding --keys)
read -r BOB_WIF   _          < <(./test/mkfunding --keys)
BOB_PUB=$(./bob --wif "$BOB_WIF" --pubkey)
CHANNEL=$(./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" \
                  --locktime "$LOCKTIME" --address)
read -r FUNDING_HEX _ _ < <(./test/mkfunding "$CHANNEL" "$ALICE_ADDR" 100.0)
printf '%s' "$FUNDING_HEX" > "$WORK/funding.hex"

set_height() { printf '%s\n' "$1" > "$WORK/height"; }

# slack 100 against locktime 300000: room below 299900, none at or above it
set_height 200000
./bob --wif "$BOB_WIF" --listen "127.0.0.1:$PORT" --trust-peer --min-slack 100 \
      --height-file "$WORK/height" --state "$WORK/state" \
      --price 5.0 > "$WORK/bob.log" 2>&1 &
BOB_PID=$!
for _ in $(seq 1 100); do
    grep -q "listening" "$WORK/bob.log" 2>/dev/null && break
    sleep 0.1
done
[ -n "$BOB_PID" ] || { echo "FAIL: bob never listened" >&2; exit 1; }

open_channel() {
    ./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
            --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$PORT" \
            --max 100.0 > "$WORK/alice-$1.log" 2>&1 || true
}

fail=0
say() { printf "  %-50s %s\n" "$1" "$2"; }

echo "height, re-read per channel:"

open_channel far
if grep -qi "invoice\|accepted" "$WORK/alice-far.log"; then
    say "height 200000, locktime 300000: opens" "yes"
else
    say "height 200000, locktime 300000: opens" "refused"; fail=1
fi

# nothing restarts. only the number under bob changes.
set_height 299950
open_channel near
if grep -qi "too near" "$WORK/alice-near.log"; then
    say "height 299950, same channel: refused as too near" "yes"
else
    say "height 299950, same channel: refused as too near" "accepted"; fail=1
fi

set_height 400000
open_channel past
if grep -qi "too near" "$WORK/alice-past.log"; then
    say "height 400000, locktime already passed: refused" "yes"
else
    say "height 400000, locktime already passed: refused" "accepted"; fail=1
fi

# and a file nobody is updating is not a height, it is a memory
set_height 200000
touch -d "2 hours ago" "$WORK/height"
open_channel stale
if grep -qi "stale" "$WORK/alice-stale.log"; then
    say "nothing updating the file: refused as stale" "yes"
else
    say "nothing updating the file: refused as stale" "accepted"; fail=1
fi

kill "$BOB_PID" 2>/dev/null || true
wait "$BOB_PID" 2>/dev/null || true
BOB_PID=

[ "$fail" = 0 ] || { echo "height FAILED" >&2; exit 1; }
echo "height ok"
