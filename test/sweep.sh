#!/usr/bin/env bash
# A payment nobody closed on still reaches the chain.
#
# A session that ends without a close leaves the transaction in its state file
# and the child exits. Nothing read that back, so if alice paid and walked away
# it sat there until the locktime passed and her refund took the money and the
# goods with it. The ratchet and --broadcast-cmd each solved half of that and
# the halves were not joined.
#
# What this pins: a channel with time left is left alone, one near its locktime
# is broadcast and retired, one a live session holds is skipped rather than
# swept out from under it, and one whose funding has gone is retired without a
# broadcast rather than sending a transaction that cannot confirm.
set -eu

cd "$(dirname "$0")/.."
PORT=${PORT:-19889}
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

cat > "$WORK/confirm" <<'STUB'
#!/usr/bin/env bash
case "$(cat "$CONFIRM_ANSWER")" in
  ok)     echo "unspent height 900 depth 100 value 10000000000 koinu"; exit 0 ;;
  gone)   echo "not found (unconfirmed or already spent)"; exit 3 ;;
  broken) echo "the node fell over" >&2; exit 1 ;;
esac
STUB
cat > "$WORK/send" <<'SEND'
#!/usr/bin/env bash
read -r hex
[ ${#hex} -gt 100 ] || { echo "no transaction on stdin" >&2; exit 1; }
echo "broadcast: ${hex:0:64} (no reject)"
printf '%s\n' "${hex:0:64}" >> "$SENT_LOG"
SEND
chmod +x "$WORK/confirm" "$WORK/send"
export CONFIRM_ANSWER="$WORK/answer" SENT_LOG="$WORK/sent"
echo ok > "$CONFIRM_ANSWER"; : > "$SENT_LOG"

# alice pays and disconnects. no --close, which is the whole point.
./bob --wif "$BOB_WIF" --listen "127.0.0.1:$PORT" --min-slack 100 \
      --height-file "$WORK/height" --state "$WORK/state" \
      --price 5.0 > "$WORK/bob.log" 2>&1 &
BOB_PID=$!
for _ in $(seq 1 100); do
    grep -q "listening" "$WORK/bob.log" 2>/dev/null && break
    sleep 0.1
done
./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
        --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$PORT" \
        --max 100.0 > "$WORK/alice.log" 2>&1 || true
kill "$BOB_PID" 2>/dev/null || true; wait "$BOB_PID" 2>/dev/null || true; BOB_PID=

cp "$WORK"/state/*.channel "$WORK/pristine"

fail=0
say() { printf "  %-50s %s\n" "$1" "$2"; }
sweep() {
    ./bob --sweep --state "$WORK/state" --height-file "$WORK/height" \
          --broadcast-cmd "$WORK/send" --confirm-cmd "$WORK/confirm" \
          --sweep-margin "${1:-50}" > "$WORK/sweep.log" 2>&1 || true
    tail -1 "$WORK/sweep.log"
}

echo "a payment nobody closed on:"

grep -q "^paid " "$WORK/state"/*.channel \
    && say "the payment is on disk after the session ends" "yes" \
    || { say "the payment is on disk after the session ends" "no"; fail=1; }

# height 1000, locktime 300000: nowhere near, so leave it alone
sweep 50 | grep -qE "0 broadcast, .*1 waiting" \
    && say "a channel with time left is left alone" "yes" \
    || { say "a channel with time left is left alone" "$(sweep 50)"; fail=1; }
[ ! -s "$SENT_LOG" ] || { say "and nothing was sent" "something was"; fail=1; }

# a session holding it is skipped rather than swept from under the peer
python3 - "$WORK"/state/*.channel.lock <<'LOCK' &
import fcntl, sys, time
f = open(sys.argv[1], "r+"); fcntl.flock(f, fcntl.LOCK_EX)
print("held", flush=True); time.sleep(8)
LOCK
HOLD=$!
sleep 1
sweep 400000 | grep -q "1 held by a session" \
    && say "a channel a live session holds is skipped" "yes" \
    || { say "a channel a live session holds is skipped" "not skipped"; fail=1; }
kill "$HOLD" 2>/dev/null || true; wait "$HOLD" 2>/dev/null || true

# now inside the margin: broadcast it, but do not call it finished
sweep 400000 | grep -q "1 broadcast" \
    && say "one near its locktime is broadcast" "yes" \
    || { say "one near its locktime is broadcast" "no"; fail=1; }
[ -s "$SENT_LOG" ] \
    && say "and the transaction actually left" "$(wc -l < "$SENT_LOG") sent" \
    || { say "and the transaction actually left" "nothing sent"; fail=1; }

# kw send says "no reject", not "accepted". A peer may never relay it and a
# mempool may drop it, and nothing sweeps a retired channel again, so retiring
# here would finish the channel on Bob's side while it is unspent on the chain.
grep -q "^closed 0" "$WORK"/state/*.channel && grep -q "^sent 1" "$WORK"/state/*.channel \
    && say "sent is recorded, the channel is not retired" "yes" \
    || { say "sent is recorded, the channel is not retired" "no"; fail=1; }

# still unspent on the next pass: send it again rather than assume
: > "$SENT_LOG"
sweep 400000 | grep -q "1 broadcast" \
    && say "still unspent next pass, so it sends again" "yes" \
    || { say "still unspent next pass, so it sends again" "no"; fail=1; }
[ -s "$SENT_LOG" ] || { say "and that resend actually left" "nothing"; fail=1; }

# the outpoint going away is what confirmation looks like from outside
echo gone > "$CONFIRM_ANSWER"
: > "$SENT_LOG"
sweep 400000 | grep -q "1 confirmed" \
    && say "the outpoint being spent is what retires it" "yes" \
    || { say "the outpoint being spent is what retires it" "no"; fail=1; }
grep -q "^closed 1" "$WORK"/state/*.channel \
    && say "and only then is the channel closed" "yes" \
    || { say "and only then is the channel closed" "no"; fail=1; }
[ ! -s "$SENT_LOG" ] || { say "and it sent nothing that pass" "it did"; fail=1; }
sweep 400000 | grep -q "0 broadcast" \
    && say "a pass after that does nothing" "yes" \
    || { say "a pass after that does nothing" "no"; fail=1; }
echo ok > "$CONFIRM_ANSWER"

# A backend that cannot answer is not a backend saying the output is gone.
# Collapsing the two retires the channel and drops the payment, which is the one
# outcome worse than doing nothing, and it is what this did until a real kw
# failed against a real chain and retired a real payment.
rm -rf "$WORK/state3"; mkdir -p "$WORK/state3"
cp "$WORK/pristine" "$WORK/state3/$(basename "$(ls "$WORK"/state/*.channel)")"
echo broken > "$CONFIRM_ANSWER"
: > "$SENT_LOG"
./bob --sweep --state "$WORK/state3" --height-file "$WORK/height" \
      --broadcast-cmd "$WORK/send" --confirm-cmd "$WORK/confirm" \
      --sweep-margin 400000 > "$WORK/sweep3.log" 2>&1 || true
if grep -q "leaving it for the next pass" "$WORK/sweep3.log" \
   && grep -q "^closed 0" "$WORK"/state3/*.channel && [ ! -s "$SENT_LOG" ]; then
    say "a backend that cannot answer retires nothing" "yes"
else
    say "a backend that cannot answer retires nothing" "$(tail -1 "$WORK/sweep3.log")"; fail=1
fi

# a funding output that has gone: retire it, do not send a dead transaction
rm -rf "$WORK/state2"; mkdir -p "$WORK/state2"
cp "$WORK/pristine" "$WORK/state2/$(basename "$(ls "$WORK"/state/*.channel)")"
echo gone > "$CONFIRM_ANSWER"
: > "$SENT_LOG"
./bob --sweep --state "$WORK/state2" --height-file "$WORK/height" \
      --broadcast-cmd "$WORK/send" --confirm-cmd "$WORK/confirm" \
      --sweep-margin 400000 > "$WORK/sweep2.log" 2>&1 || true
if grep -q "unconfirmed or spent" "$WORK/sweep2.log" && [ ! -s "$SENT_LOG" ]; then
    say "a channel whose funding is gone is not sent" "yes"
else
    say "a channel whose funding is gone is not sent" "$(tail -1 "$WORK/sweep2.log")"; fail=1
fi

# A closed channel is not a finished one. Closing refuses new sessions on the
# outpoint; what finishes it is that outpoint being spent. Skipping closed
# channels here switched the safety net off at the moment it was needed: a close
# with no --broadcast-cmd, or one interrupted between retiring and sending, left
# the transaction in the file with nothing that would ever send it.
rm -rf "$WORK/state4"; mkdir -p "$WORK/state4"
python3 - "$WORK/pristine" "$WORK/state4/$(basename "$(ls "$WORK"/state/*.channel)")" <<'CLOSEIT'
import sys
src, dst = sys.argv[1], sys.argv[2]
body = open(src).read().replace("closed 0", "closed 1")
open(dst, "w").write(body)
CLOSEIT
echo ok > "$CONFIRM_ANSWER"
: > "$SENT_LOG"
SW4() {
    ./bob --sweep --state "$WORK/state4" --height-file "$WORK/height" \
          --broadcast-cmd "$WORK/send" --confirm-cmd "$WORK/confirm" \
          --sweep-margin 50 2>&1 | tail -1
}
# margin 50 against a locktime of 300000 at height 1000: an open channel would
# wait, a closed one is due now
SW4 | grep -q "1 broadcast" \
    && say "a closed channel is broadcast, not skipped" "yes" \
    || { say "a closed channel is broadcast, not skipped" "no"; fail=1; }
[ -s "$SENT_LOG" ] || { say "and it actually left" "nothing"; fail=1; }
grep -q "^closed 1" "$WORK"/state4/*.channel && grep -q "^sent 1" "$WORK"/state4/*.channel \
    && say "and it stays closed while it is tracked" "yes" \
    || { say "and it stays closed while it is tracked" "no"; fail=1; }
echo gone > "$CONFIRM_ANSWER"
SW4 | grep -q "1 confirmed" \
    && say "spending the outpoint reports it confirmed" "yes" \
    || { say "spending the outpoint reports it confirmed" "$(SW4)"; fail=1; }

[ "$fail" = 0 ] || { echo "sweep FAILED" >&2; exit 1; }
echo "sweep ok"
