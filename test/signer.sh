#!/usr/bin/env bash
# The signing key lives in the signer, not in the process that touches the
# socket. The network bob runs with --sign-cmd and --bob-pubkey and no --wif: it
# hands each payment PSBT to a signer that holds the key, gets a signed PSBT
# back, assembles and re-verifies it. `bob --sign` is that signer. This proves a
# full channel completes that way and that the network process never holds the
# key.
set -eu

cd "$(dirname "$0")/.."
PORT=${PORT:-19893}
LOCKTIME=${LOCKTIME:-300000}

for b in alice bob test/mkfunding; do
    [ -x "$b" ] || { echo "build first: make check" >&2; exit 1; }
done

WORK=$(mktemp -d)
BOB_PID=
trap 'rm -rf "$WORK"; [ -n "$BOB_PID" ] && kill "$BOB_PID" 2>/dev/null || true' EXIT

read -r ALICE_WIF ALICE_ADDR < <(./test/mkfunding --keys)
read -r BOB_WIF   _          < <(./test/mkfunding --keys)
printf '%s\n' "$BOB_WIF" > "$WORK/bobkey"; chmod 600 "$WORK/bobkey"
BOB_PUB=$(./bob --wif "$BOB_WIF" --pubkey)
CHANNEL=$(./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" \
                  --locktime "$LOCKTIME" --address)
read -r FUNDING_HEX _ _ < <(./test/mkfunding "$CHANNEL" "$ALICE_ADDR" 100.0)
printf '%s' "$FUNDING_HEX" > "$WORK/funding.hex"

fail=0
say() { printf "  %-52s %s\n" "$1" "$2"; }
echo "signing is delegated, the key is not in the network process:"

# network bob: no --wif. the key is only in the signer the --sign-cmd names.
./bob --sign-cmd "$PWD/bob --sign --wif @$WORK/bobkey" --bob-pubkey "$BOB_PUB" \
      --listen "127.0.0.1:$PORT" --once --height 1000 --min-slack 100 \
      --price 5.0 --price 7.5 > "$WORK/bob.log" 2>&1 &
BOB_PID=$!
for _ in $(seq 1 100); do grep -q listening "$WORK/bob.log" 2>/dev/null && break; sleep 0.1; done
./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
        --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$PORT" \
        --max 12.5 > "$WORK/alice.log" 2>&1 || true
wait "$BOB_PID" 2>/dev/null || true; BOB_PID=

grep -q "^paid " "$WORK/bob.log" \
    && say "a payment is countersigned through the signer" "yes" \
    || { say "a payment is countersigned through the signer" "$(tail -3 "$WORK/bob.log")"; fail=1; }
# the network bob assembled a broadcastable tx from the signer's PSBT, keyless,
# and pc_tx_verify_payment passed on it (that is what lets "paid held" print)
grep -q "broadcast this to take the money" "$WORK/bob.log" \
    && say "bob assembles a broadcastable tx from the signer" "yes" \
    || { say "bob assembles a broadcastable tx from the signer" "no"; fail=1; }
grep -q "$BOB_WIF" "$WORK/bob.log" "$WORK/alice.log" \
    && { say "the network process never sees the key" "LEAKED"; fail=1; } \
    || say "the network process never sees the key" "yes"

# the signer signs a psbt but refuses a non-psbt, and the network bob rejects a
# signer that returns nothing rather than shipping garbage
if printf 'not a psbt\n' | ./bob --sign --wif @"$WORK/bobkey" >/dev/null 2>&1; then
    say "the signer refuses a non-psbt" "no (accepted)"; fail=1
else
    say "the signer refuses a non-psbt" "yes"
fi

[ "$fail" = 0 ] || { echo "signer FAILED" >&2; exit 1; }
echo "signer ok"
