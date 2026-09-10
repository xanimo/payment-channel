#!/usr/bin/env bash
# --metrics-file on a serving bob. The counters live in a shared mapping made
# before the first fork, so this proves a child's work reaches the parent's
# snapshot: a connection served in another process still shows up as payments,
# koinu received and a close. Also that a refusal is counted, and that the file
# is a complete snapshot rather than a half-written one.
set -eu

cd "$(dirname "$0")/.."
PORT=${PORT:-19881}
LOCKTIME=${LOCKTIME:-300000}

for b in alice bob test/mkfunding; do
    [ -x "$b" ] || { echo "build first: make check" >&2; exit 1; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; [ -n "${BOB_PID:-}" ] && kill "$BOB_PID" 2>/dev/null || true' EXIT
fail=0
say() { printf "  %-52s %s\n" "$1" "$2"; }

# the value of a counter in the snapshot, or empty if the file lacks it
m() { sed -n "s/^$1 //p" "$WORK/metrics.prom"; }

read -r ALICE_WIF ALICE_ADDR < <(./test/mkfunding --keys)
read -r BOB_WIF   _          < <(./test/mkfunding --keys)
BOB_PUB=$(./bob --wif "$BOB_WIF" --pubkey)

CHANNEL=$(./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" \
                  --locktime "$LOCKTIME" --address)
read -r FUNDING_HEX _ _ < <(./test/mkfunding "$CHANNEL" "$ALICE_ADDR" 100.0)
printf '%s' "$FUNDING_HEX" > "$WORK/funding.hex"

echo "serving metrics:"

mkdir -p "$WORK/state"
./bob --wif "$BOB_WIF" --listen "127.0.0.1:$PORT" --once \
      --height 1000 --min-slack 100 --state "$WORK/state" \
      --metrics-file "$WORK/metrics.prom" \
      --price 5.0 --price 7.5 --price 17.5 > "$WORK/bob.log" 2>&1 &
BOB_PID=$!

for _ in $(seq 1 50); do
    grep -q "listening" "$WORK/bob.log" 2>/dev/null && break
    sleep 0.1
done

./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
        --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$PORT" \
        --max 100.0 --close > "$WORK/alice.log" 2>&1

wait "$BOB_PID" || true
BOB_PID=

[ -f "$WORK/metrics.prom" ] || { echo "FAIL: no metrics file written" >&2; exit 1; }

# the child served the whole session in its own process; every number below
# was incremented there and read back here from the parent's snapshot.
[ "$(m pc_serve_connections_total)" = "1" ] &&
    say "a forked connection is counted" yes ||
    { say "connections" "$(m pc_serve_connections_total)"; fail=1; }

[ "$(m pc_serve_opens_total)" = "1" ] &&
    say "the child's open reaches the parent" yes ||
    { say "opens" "$(m pc_serve_opens_total)"; fail=1; }

# three prices, so three payments totalling 30 DOGE
[ "$(m pc_serve_payments_total)" = "3" ] &&
    say "all three payments are counted" yes ||
    { say "payments" "$(m pc_serve_payments_total)"; fail=1; }

[ "$(m pc_serve_received_koinu_total)" = "3000000000" ] &&
    say "koinu received is the cumulative total" yes ||
    { say "received_koinu" "$(m pc_serve_received_koinu_total)"; fail=1; }

[ "$(m pc_serve_closes_total)" = "1" ] &&
    say "the close is counted" yes ||
    { say "closes" "$(m pc_serve_closes_total)"; fail=1; }

[ "$(m pc_serve_rejects_total)" = "0" ] &&
    say "an honest session rejects nothing" yes ||
    { say "rejects" "$(m pc_serve_rejects_total)"; fail=1; }

[ "$(m pc_serve_live_connections)" = "0" ] &&
    say "the gauge is back to zero on exit" yes ||
    { say "live_connections" "$(m pc_serve_live_connections)"; fail=1; }

# every counter the writer names is present: a scraper reading a partial file
# would report a drop to zero rather than a gap.
want=13
got=$(grep -c "^pc_serve_" "$WORK/metrics.prom")
[ "$got" = "$want" ] &&
    say "the snapshot is complete ($want series)" yes ||
    { say "series in snapshot" "$got, want $want"; fail=1; }

# A rejection is counted too. Bob refuses a locktime that does not clear
# --min-slack, and Alice never gets as far as a payment.
mkdir -p "$WORK/state2"
./bob --wif "$BOB_WIF" --listen "127.0.0.1:$((PORT+1))" --once \
      --height 1000 --min-slack 100 --state "$WORK/state2" \
      --metrics-file "$WORK/metrics.prom" \
      --price 5.0 > "$WORK/bob2.log" 2>&1 &
BOB_PID=$!
for _ in $(seq 1 50); do
    grep -q "listening" "$WORK/bob2.log" 2>/dev/null && break
    sleep 0.1
done

CH2=$(./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime 1050 --address)
read -r F2 _ _ < <(./test/mkfunding "$CH2" "$ALICE_ADDR" 100.0)
printf '%s' "$F2" > "$WORK/f2.hex"
./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime 1050 \
        --funding-tx "@$WORK/f2.hex" --connect "127.0.0.1:$((PORT+1))" \
        --max 100.0 --close > "$WORK/alice2.log" 2>&1 || true
wait "$BOB_PID" || true
BOB_PID=

[ "$(m pc_serve_rejects_total)" -ge 1 ] &&
    say "a refused channel is counted as a reject" yes ||
    { say "rejects after refusal" "$(m pc_serve_rejects_total)"; fail=1; }

[ "$(m pc_serve_payments_total)" = "0" ] &&
    say "and it paid nothing" yes ||
    { say "payments after refusal" "$(m pc_serve_payments_total)"; fail=1; }

[ "$fail" = 0 ] || { echo "metrics FAILED" >&2; exit 1; }
echo "metrics ok"
