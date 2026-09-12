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
# A stub stands in for it here so the cases are testable without a node: too
# shallow, spent, a value that disagrees, a backend that hangs. What a stub
# cannot check is whether the contract itself is right, since one written from
# the same reading as the code agrees with the code and with nothing else.
# contrib/regtest.sh runs the real kw against a real chain for that.
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
# The operator's own arguments come first and Bob's two are appended, which is
# the shape kw outpoint needs since it requires --node. A single-path
# --confirm-cmd could never invoke it, and the first version of this stub took
# one path and so never noticed.
[ "$1" = "--node" ] && [ "$2" = "stub" ] || { echo "operator args lost" >&2; exit 1; }
[ "$3" = "--watch" ] && [ "$5" = "--outpoint" ] || { echo "bad argv" >&2; exit 1; }
# --since is appended only when --since-window asked for it, because it needs a
# filter cache and a backend without one rejects it as an unknown option
printf '%s\n' "${7:-none} ${8:-}" > "$SINCE_SEEN"
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
cat > "$WORK/send" <<'SEND'
#!/usr/bin/env bash
# kw send takes the hex on stdin with --tx -
[ "$1" = "--node" ] && [ "$3" = "--tx" ] && [ "$4" = "-" ] || { echo "bad argv" >&2; exit 1; }
read -r hex
[ ${#hex} -gt 100 ] || { echo "no transaction on stdin" >&2; exit 1; }
case "$(cat "$SEND_ANSWER")" in
  ok)       echo "broadcast: ${hex:0:64} (no reject)"; exit 0 ;;
  rejected) echo "rejected: bad-txns-inputs-missingorspent" >&2; exit 1 ;;
esac
SEND
chmod +x "$WORK/send"
export SEND_ANSWER="$WORK/sendanswer"
echo ok > "$SEND_ANSWER"
chmod +x "$WORK/confirm"
export SINCE_SEEN="$WORK/since"
export CONFIRM_ANSWER="$WORK/answer"

answer() { printf '%s %s\n' "$1" "${2:-0}" > "$WORK/answer"; }

answer unspent 100
./bob --wif "$BOB_WIF" --listen "127.0.0.1:$PORT" --min-slack 100 \
      --height-file "$WORK/height" --state "$WORK/state" \
      --confirm-cmd "$WORK/confirm --node stub" --min-depth 6 \
      --broadcast-cmd "$WORK/send --node stub" \
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

# closing hands the transaction to the chain rather than to the operator, which
# is what shrinks the window alice's refund is racing
answer unspent 100
./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
        --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$PORT" \
        --max 100.0 --close > "$WORK/alice-close.log" 2>&1 || true
for _ in $(seq 1 40); do grep -q "broadcast:" "$WORK/bob.log" && break; sleep 0.25; done
grep -q "broadcast:" "$WORK/bob.log" \
    && say "the close is broadcast, not printed for a human" "yes" \
    || { say "the close is broadcast, not printed for a human" "no"; fail=1; }
grep -q "sent, keep this in case" "$WORK/bob.log" \
    && say "and it stops asking the operator to send it" "yes" \
    || { say "and it stops asking the operator to send it" "no"; fail=1; }

# by default nothing is appended, so a backend with no filter cache still works
grep -q "^none" "$SINCE_SEEN" \
    && say "no --since unless it was asked for" "yes" \
    || { say "no --since unless it was asked for" "$(cat "$SINCE_SEEN")"; fail=1; }

kill "$BOB_PID" 2>/dev/null || true
wait "$BOB_PID" 2>/dev/null || true
BOB_PID=

# with a window, --since is appended and is height minus the window
answer unspent 100
: > "$SINCE_SEEN"
mkdir -p "$WORK/state2"
./bob --wif "$BOB_WIF" --listen "127.0.0.1:$((PORT + 1))" --once --min-slack 100 \
      --height-file "$WORK/height" --state "$WORK/state2" \
      --confirm-cmd "$WORK/confirm --node stub" --min-depth 6 \
      --since-window 400 --price 5.0 > "$WORK/bob2.log" 2>&1 &
B2=$!
for _ in $(seq 1 100); do grep -q listening "$WORK/bob2.log" 2>/dev/null && break; sleep 0.1; done
./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
        --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$((PORT + 1))" \
        --max 100.0 > "$WORK/alice-since.log" 2>&1 || true
kill "$B2" 2>/dev/null || true; wait "$B2" 2>/dev/null || true
# height file says 1000, window 400, so it should ask from 600
grep -q "^--since 600" "$SINCE_SEEN" \
    && say "with a window it asks from height minus it" "yes" \
    || { say "with a window it asks from height minus it" "$(cat "$SINCE_SEEN")"; fail=1; }
grep -q "^fheight 900" "$WORK/state2"/*.channel 2>/dev/null \
    && say "and records where the funding was found" "yes" \
    || { say "and records where the funding was found" "$(grep -h '^fheight' "$WORK/state2"/*.channel 2>/dev/null)"; fail=1; }

# A backend path with a space in it. Splitting on whitespace alone made this
# unreachable: the operator could not name the program at all, and it failed
# closed as "cannot confirm" with nothing pointing at the path. Quotes and a
# backslash both have to carry it through to execvp.
SPACED="$WORK/dir with space"
mkdir -p "$SPACED" "$WORK/state3" "$WORK/state4"
cp "$WORK/confirm" "$SPACED/confirm"
answer unspent 100

spaced_open() {
    ./bob --wif "$BOB_WIF" --listen "127.0.0.1:$2" --min-slack 100 --once \
          --height-file "$WORK/height" --state "$WORK/$3" \
          --confirm-cmd "$1" --min-depth 6 --price 5.0 \
          > "$WORK/bob-$3.log" 2>&1 &
    local p=$!
    for _ in $(seq 1 100); do
        grep -q listening "$WORK/bob-$3.log" 2>/dev/null && break
        sleep 0.1
    done
    ./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
            --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$2" \
            --max 100.0 > "$WORK/alice-$3.log" 2>&1 || true
    wait "$p" 2>/dev/null || true
}

spaced_open "'$SPACED/confirm' --node stub" "$((PORT+7))" state3
grep -q "funding  confirmed" "$WORK/bob-state3.log" \
    && say "a quoted backend path with a space runs" "yes" \
    || { say "a quoted backend path with a space runs" "$(tail -1 "$WORK/bob-state3.log")"; fail=1; }

spaced_open "$WORK/dir\\ with\\ space/confirm --node stub" "$((PORT+8))" state4
grep -q "funding  confirmed" "$WORK/bob-state4.log" \
    && say "and a backslash-escaped one" "yes" \
    || { say "and a backslash-escaped one" "$(tail -1 "$WORK/bob-state4.log")"; fail=1; }

# Serving with no backend at all is refused, the same shape as --state and
# --height-file. Without one nothing consults a chain, so a funding Alice never
# broadcast passes every check here, because every check here is arithmetic over
# bytes she supplied.
out=$(./bob --wif "$BOB_WIF" --listen "127.0.0.1:$((PORT+9))" --min-slack 100 \
            --height-file "$WORK/height" --state "$WORK/state" --price 5.0 2>&1 || true)
printf '%s' "$out" | grep -q "confirm-cmd CMD is required" \
    && say "serving with no chain check is refused" "yes" \
    || { say "serving with no chain check is refused" "$(printf '%s' "$out" | head -1)"; fail=1; }

printf '%s' "$out" | grep -q "trust-peer" \
    && say "and it names the opt-out" "yes" \
    || { say "and it names the opt-out" "no"; fail=1; }

# A backend that reports a depth and no value used to have Alice's claimed
# capacity accepted with nothing contradicting it. Capacity is the bound every
# amount check downstream is measured against.
cat > "$WORK/depthonly" <<'DO'
#!/usr/bin/env bash
echo "unspent height 900 depth 100"
DO
chmod +x "$WORK/depthonly"
mkdir -p "$WORK/state9"
./bob --wif "$BOB_WIF" --listen "127.0.0.1:$((PORT+10))" --min-slack 100 --once \
      --height-file "$WORK/height" --state "$WORK/state9" \
      --confirm-cmd "$WORK/depthonly" --min-depth 6 --price 5.0 \
      > "$WORK/bob-depthonly.log" 2>&1 &
DP=$!
for _ in $(seq 1 100); do grep -q listening "$WORK/bob-depthonly.log" 2>/dev/null && break; sleep 0.1; done
./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
        --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$((PORT+10))" \
        --max 100.0 > "$WORK/alice-depthonly.log" 2>&1 || true
wait "$DP" 2>/dev/null || true
grep -qi "no value" "$WORK/alice-depthonly.log" \
    && say "a backend that gives no value is refused" "yes" \
    || { say "a backend that gives no value is refused" "$(grep -i reject "$WORK/alice-depthonly.log" | head -1)"; fail=1; }

[ "$fail" = 0 ] || { echo "confirm FAILED" >&2; exit 1; }
echo "confirm ok"
