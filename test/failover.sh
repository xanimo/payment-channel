#!/usr/bin/env bash
# The drill doc/RUNBOOK.md describes, run for real: take a payment, destroy the
# primary state directory outright, and recover the money from the replica
# alone. replicate.sh proves the bytes arrive; this proves they are enough.
#
# What makes it work is that pc_state_adopt rebuilds the channel from the file:
# the sweep needs no key, no session and no memory of the channel, so a replica
# directory is a working primary rather than a backup that needs restoring into
# something.
set -eu

cd "$(dirname "$0")/.."
PORT=${PORT:-19897}
LOCKTIME=${LOCKTIME:-300000}
for b in alice bob test/mkfunding; do
    [ -x "$b" ] || { echo "build first: make check" >&2; exit 1; }
done

WORK=$(mktemp -d)
BOB_PID=
trap 'rm -rf "$WORK"; [ -n "$BOB_PID" ] && kill "$BOB_PID" 2>/dev/null || true' EXIT
mkdir -p "$WORK/primary" "$WORK/replica"
fail=0
say() { printf "  %-52s %s\n" "$1" "$2"; }

# a broadcast stub that records what it was handed, standing in for `kw send`
cat > "$WORK/send" <<'EOF'
#!/usr/bin/env bash
cat >> "$(dirname "$0")/sent.hex"
echo "no reject"
EOF
chmod +x "$WORK/send"
echo 1000 > "$WORK/height"

read -r ALICE_WIF ALICE_ADDR < <(./test/mkfunding --keys)
read -r BOB_WIF   _          < <(./test/mkfunding --keys)
BOB_PUB=$(./bob --wif "$BOB_WIF" --pubkey)
CHANNEL=$(./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" --address)
read -r FUNDING_HEX _ _ < <(./test/mkfunding "$CHANNEL" "$ALICE_ADDR" 100.0)
printf '%s' "$FUNDING_HEX" > "$WORK/funding.hex"

echo "recovering a payment from the replica after the primary is gone:"

# Alice pays, Bob saves to primary and mirrors to replica before acking.
./bob --wif "$BOB_WIF" --listen "127.0.0.1:$PORT" --once --height 1000 \
      --min-slack 100 --state "$WORK/primary" --price 5.0 \
      --replicate-cmd "cp -t $WORK/replica" > "$WORK/bob.log" 2>&1 &
BOB_PID=$!
for _ in $(seq 1 100); do grep -q listening "$WORK/bob.log" 2>/dev/null && break; sleep 0.1; done
./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
        --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$PORT" \
        --max 5.0 > "$WORK/alice.log" 2>&1 || true
wait "$BOB_PID" 2>/dev/null || true; BOB_PID=

grep -q "koinu held" "$WORK/bob.log" \
    && say "a payment is taken and acked" yes \
    || { say "a payment is taken" "no"; fail=1; }

PAID=$(sed -n 's/^paid *\([0-9]*\) koinu held.*/\1/p' "$WORK/bob.log" | tail -1)
[ -n "$PAID" ] && [ "$PAID" -gt 0 ] \
    && say "worth $PAID koinu" yes \
    || { say "amount not readable from the log" "$PAID"; fail=1; }

# The disk dies. Not a corrupted file, not a stale one: gone, along with any
# lock it held, which is the case a backup story has to survive.
rm -rf "$WORK/primary"
[ ! -d "$WORK/primary" ] \
    && say "the primary state directory is destroyed" yes \
    || { say "primary still present" no; fail=1; }

# Failover is pointing the sweep at the replica. No key, no restore step, no
# edit to the files: the sweep is the same command it always was.
./bob --sweep --state "$WORK/replica" --height-file "$WORK/height" \
      --broadcast-cmd "$WORK/send" --sweep-margin 400000 \
      > "$WORK/sweep.log" 2>&1 || true

grep -q "1 broadcast" "$WORK/sweep.log" \
    && say "the replica alone broadcasts the payment" yes \
    || { say "sweep from replica" "$(tail -1 "$WORK/sweep.log")"; fail=1; }

# the money is real: what went to the broadcaster is a transaction, and it is
# the one the channel was holding
[ -s "$WORK/sent.hex" ] \
    && say "a transaction reached the broadcaster" yes \
    || { say "nothing was broadcast" no; fail=1; }

if grep -q "at_risk_koinu=$PAID" "$WORK/sweep.log"; then
    say "and it carries the koinu the primary had taken" yes
else
    say "at_risk does not match the payment" "$(grep -o 'at_risk_koinu=[0-9]*' "$WORK/sweep.log" | tail -1), want $PAID"
    fail=1
fi

# A second pass must not send it twice as a matter of course: the channel is
# only retired once the chain shows the outpoint spent, so it re-sends, which
# is deliberate and is what the runbook warns about.
./bob --sweep --state "$WORK/replica" --height-file "$WORK/height" \
      --broadcast-cmd "$WORK/send" --sweep-margin 400000 \
      > "$WORK/sweep2.log" 2>&1 || true
grep -q "sweep-status" "$WORK/sweep2.log" \
    && say "a second pass still runs against the replica" yes \
    || { say "second pass" "$(tail -1 "$WORK/sweep2.log")"; fail=1; }

# The recovered directory is now the primary, so it must replicate onward
# exactly as the old one did rather than being a dead end.
mkdir -p "$WORK/replica2"
./bob --sweep --state "$WORK/replica" --height-file "$WORK/height" \
      --broadcast-cmd "$WORK/send" --sweep-margin 400000 \
      --replicate-cmd "cp -t $WORK/replica2" > "$WORK/sweep3.log" 2>&1 || true
ls "$WORK/replica2"/*.channel >/dev/null 2>&1 \
    && say "and replicates onward as the new primary" yes \
    || { say "promoted replica does not replicate" no; fail=1; }

[ "$fail" = 0 ] || { echo "failover FAILED" >&2; exit 1; }
echo "failover ok"
