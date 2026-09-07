#!/usr/bin/env bash
# The funding output is checked against a chain, not against Alice.
#
# Everything else Bob knows about the funding comes from a transaction she sent
# him. She never has to have broadcast it, it may have been double spent, an
# earlier close may have already spent it, or her own refund may have swept it.
# All four end the same way: Bob ships against a transaction that can never
# confirm.
#
# --confirm-cmd is the only thing that turns "she showed me a transaction" into
# "the chain has this output". The contract is koinu's kw outpoint:
#
#   CMD --watch ADDR --outpoint TXID:VOUT
#   exit 0 and "unspent height H depth D value V koinu"   confirmed
#   exit 3 and "not found (unconfirmed or already spent)" not
#
# A stub stands in for it here so the integration is testable without a node.
# contrib/regtest.sh is where the real one belongs.
set -eu

cd "$(dirname "$0")/.."
PORT=${PORT:-19888}
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

# the stub reads its answer from a file, so one running Bob can be told
# different things about the same outpoint
cat > "$WORK/confirm" <<'STUB'
#!/usr/bin/env bash
# argv is: --watch ADDR --outpoint TXID:VOUT, exactly what kw outpoint takes
[ "$1" = "--watch" ] && [ "$3" = "--outpoint" ] || { echo "bad argv" >&2; exit 1; }
read -r mode arg < "$CONFIRM_ANSWER"
case "$mode" in
  unspent) echo "unspent height 900 depth $arg value 10000000000 koinu"; exit 0 ;;
  wrongvalue) echo "unspent height 900 depth 100 value $arg koinu"; exit 0 ;;
  notfound) echo "not found (unconfirmed or already spent)"; exit 3 ;;
  hang)    sleep 120; exit 0 ;;
  broken)  echo "unspent but who knows"; exit 0 ;;
  crash)   exit 1 ;;
esac
STUB
chmod +x "$WORK/confirm"
export CONFIRM_ANSWER="$WORK/answer"

answer() { printf '%s %s\n' "$1" "${2:-0}" > "$WORK/answer"; }

answer unspent 100
./bob --wif "$BOB_WIF" --listen "127.0.0.1:$PORT" --min-slack 100 \
      --height-file "$WORK/height" --state "$WORK/state" \
      --confirm-cmd "$WORK/confirm" --min-depth 6 \
      --price 5.0 > "$WORK/bob.log" 2>&1 &
BOB_PID=$!
for _ in $(seq 1 100); do
    grep -q "listening" "$WORK/bob.log" 2>/dev/null && break
    sleep 0.1
done

open_channel() {
    ./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
            --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$PORT" \
            --max 100.0 > "$WORK/alice-$1.log" 2>&1 || true
}

fail=0
say() { printf "  %-48s %s\n" "$1" "$2"; }
expect_reject() {
    open_channel "$1"
    if grep -qi "$2" "$WORK/alice-$1.log"; then say "$3" "yes"
    else say "$3" "NOT REFUSED"; fail=1; fi
}

echo "funding, against a chain:"

open_channel deep
if grep -qi "invoice" "$WORK/alice-deep.log"; then
    say "confirmed to depth 100: opens" "yes"
else
    say "confirmed to depth 100: opens" "refused"; fail=1
fi

answer unspent 2
expect_reject shallow "deep enough" "depth 2 under --min-depth 6: refused"

answer notfound
expect_reject gone "unconfirmed or spent" "not in the unspent set: refused"

answer wrongvalue 500000000
expect_reject value "worth what it says" "on-chain value disagrees: refused"

answer broken
expect_reject nodepth "no depth" "an answer with no depth: refused"

answer crash
expect_reject failed "backend failed" "a backend that errors: refused"

# a backend that never answers must not pin the child open
answer hang
start=$(date +%s)
open_channel hung
took=$(( $(date +%s) - start ))
if grep -qi "did not reply" "$WORK/alice-hung.log" && [ "$took" -lt 15 ]; then
    say "a backend that hangs: dropped in ${took}s" "yes"
else
    say "a backend that hangs" "took ${took}s, $(head -1 "$WORK/alice-hung.log")"; fail=1
fi

# and it still opens once the answer is good again
answer unspent 100
open_channel recovered
grep -qi "invoice" "$WORK/alice-recovered.log" \
    && say "and opens again once confirmed" "yes" \
    || { say "and opens again once confirmed" "no"; fail=1; }

kill "$BOB_PID" 2>/dev/null || true
wait "$BOB_PID" 2>/dev/null || true
BOB_PID=

[ "$fail" = 0 ] || { echo "confirm FAILED" >&2; exit 1; }
echo "confirm ok"
