#!/usr/bin/env bash
# Cases from an outside review. Each one fails until the thing it names is
# changed, so this is not part of make check: run it with make review.
#
# Offline, with the same stub backends test/sweep.sh uses.
set -u

cd "$(dirname "$0")/.."
PORT=${PORT:-19911}
LOCKTIME=${LOCKTIME:-300000}

for b in alice bob test/mkfunding; do
    [ -x "$b" ] || { echo "build first: make review" >&2; exit 1; }
done

WORK=$(mktemp -d)
BOB_PID=
trap 'rm -rf "$WORK"; [ -n "$BOB_PID" ] && kill "$BOB_PID" 2>/dev/null || true' EXIT
mkdir -p "$WORK/state"
fail=0
say() { printf "  %-58s %s\n" "$1" "$2"; }
check() { if [ "$2" = yes ]; then say "$1" yes; else say "$1" NO; fail=$((fail + 1)); fi; }

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
  broken) echo "cannot reach daemon" >&2; exit 1 ;;
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

serve() {   # port, extra bob arguments...
    local port=$1; shift
    ./bob --wif "$BOB_WIF" --listen "127.0.0.1:$port" --trust-peer --min-slack 100 \
          --height-file "$WORK/height" "$@" --price 5.0 > "$WORK/bob.log" 2>&1 &
    BOB_PID=$!
    for _ in $(seq 1 100); do
        grep -q "listening" "$WORK/bob.log" 2>/dev/null && break
        sleep 0.1
    done
}
stop() { kill "$BOB_PID" 2>/dev/null || true; wait "$BOB_PID" 2>/dev/null || true; BOB_PID=; }

echo "a channel that is due, and a backend that cannot answer:"
printf '1000\n' > "$WORK/height"
serve "$PORT" --state "$WORK/state"
./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
        --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$PORT" \
        --max 100.0 > "$WORK/alice.log" 2>&1 || true
stop
sweep() {
    : > "$SENT_LOG"
    ./bob --sweep --state "$WORK/state" --height-file "$WORK/height" \
          --broadcast-cmd "$WORK/send" --confirm-cmd "$WORK/confirm" \
          --sweep-margin 50 > "$WORK/sweep.log" 2>&1 || true
}
cp "$WORK"/state/*.channel "$WORK/pristine"
printf '%s\n' $((LOCKTIME - 10)) > "$WORK/height"       # ten blocks from the refund
echo ok > "$CONFIRM_ANSWER"; sweep
check "control: the backend answers, the payment is broadcast" \
      "$([ -s "$SENT_LOG" ] && echo yes || echo no)"
cp "$WORK/pristine" "$WORK"/state/*.channel
echo broken > "$CONFIRM_ANSWER"; sweep
check "the backend cannot answer, the payment is still broadcast" \
      "$([ -s "$SENT_LOG" ] && echo yes || echo no)"
grep -E '^sweep +[0-9a-f]{64}' "$WORK/sweep.log" | sed 's/^/      bob said: /' | cut -c1-150

echo "a funding transaction with 34 inputs:"
# the fabricated funding has one input; repeat it under 34 different txids
F=$FUNDING_HEX
MANY="${F:0:8}22"
for i in $(seq 1 34); do MANY="$MANY$(printf '%02x' "$i")${F:12:80}"; done
MANY="$MANY${F:92}"
printf '%s' "$MANY" > "$WORK/many.hex"
printf '1000\n' > "$WORK/height"
serve "$((PORT + 1))" --once
./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
        --funding-tx "@$WORK/many.hex" --connect "127.0.0.1:$((PORT + 1))" \
        --max 100.0 > "$WORK/alice.log" 2>&1 || true
stop
OPENED=$(grep -q '^accepted' "$WORK/alice.log" && echo yes || echo no)
PAID=$(grep -q '^paid ' "$WORK/alice.log" && echo yes || echo no)
check "bob takes the opening only if alice can then pay on it" \
      "$([ "$OPENED" = no ] || [ "$PAID" = yes ] && echo yes || echo no)"
grep -E '^alice:' "$WORK/alice.log" | head -1 | sed 's/^/      /'

echo "a customer who thinks for six seconds:"
serve "$((PORT + 2))" --once
ANSWER=
if exec 3<>"/dev/tcp/127.0.0.1/$((PORT + 2))"; then
    printf '{"type":"request","psbt":"01"}\n' >&3
    read -r -t 3 _ <&3 || true
    sleep 6
    printf '{"type":"request","psbt":"01"}\n' >&3 2>/dev/null || true
    read -r -t 3 ANSWER <&3 || true
    exec 3<&- 3>&-
fi
stop
check "doc/PROTOCOL.md gives a peer thirty seconds, and bob does too" \
      "$(echo "$ANSWER" | grep -q announce && echo yes || echo no)"

# From a second pass of the same review. pc_tx_find_channel_output is what tells
# alice which output of the funding pays the channel, and alice --refund asks it
# before she builds her unilateral close. Its bounds are the opening's: at most
# KW_TX_MAX_IN inputs since c60201f, and at most PC_MAX_OUTPUTS outputs since
# before that. A funding outside them is refused with "does not pay", and by
# then it is on chain, so the refund is the one thing she still needs.
echo "the refund, for a funding the opening would refuse:"
refund() {   # funding hex file
    ./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
            --refund --funding-tx "@$1" 2>"$WORK/refund.err" | grep -cE '^[0-9a-f]{100,}$' || true
}
check "control: a funding with one input and two outputs refunds" \
      "$([ "$(refund "$WORK/funding.hex")" = 1 ] && echo yes || echo no)"
check "a funding with 34 inputs refunds" \
      "$([ "$(refund "$WORK/many.hex")" = 1 ] && echo yes || echo no)"
sed 's/^/      /' "$WORK/refund.err" | head -1
# the same funding with sixteen more outputs before its locktime, eighteen in
# all: the shape of a batch payout that happens to pay the channel
WIDE="${F:0:92}12${F:94:$(( ${#F} - 102 ))}"
for i in $(seq 1 16); do
    WIDE="$WIDE$(printf '00e1f50500000000%s%02x%s' 1976a914 "$i" 0000000000000000000000000000000000000088ac)"
done
WIDE="$WIDE${F:$(( ${#F} - 8 ))}"
printf '%s' "$WIDE" > "$WORK/wide.hex"
[ "${F:92:2}" = 02 ] || { echo "  the fabricated funding does not have two outputs; fix this case" >&2; fail=$((fail + 1)); }
check "a funding with 18 outputs refunds" \
      "$([ "$(refund "$WORK/wide.hex")" = 1 ] && echo yes || echo no)"
sed 's/^/      /' "$WORK/refund.err" | head -1

echo
if [ "$fail" -eq 0 ]; then echo "review ok"; else echo "review: $fail of these do not hold"; exit 1; fi
