#!/usr/bin/env bash
# Runs alice against bob over a real socket, with a funding transaction minted
# locally. Proves the two programs complete the protocol and that bob ends up
# holding a transaction he verified. It does not prove the transaction is valid
# to a node: contrib/regtest.sh does that.
set -eu

cd "$(dirname "$0")/.."
PORT=${PORT:-19876}
LOCKTIME=${LOCKTIME:-300000}
CAPACITY=${CAPACITY:-100.0}

for b in alice bob test/mkfunding; do
    [ -x "$b" ] || { echo "build first: make check" >&2; exit 1; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; [ -n "${BOB_PID:-}" ] && kill "$BOB_PID" 2>/dev/null || true' EXIT

# two fresh keys. no node is involved and these never see a chain.
read -r ALICE_WIF ALICE_ADDR < <(./test/mkfunding --keys)
read -r BOB_WIF   BOB_ADDR   < <(./test/mkfunding --keys)

ALICE_PUB=$(./alice --wif "$ALICE_WIF" --pubkey)
BOB_PUB=$(./bob   --wif "$BOB_WIF"   --pubkey)

CHANNEL=$(./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" \
                  --locktime "$LOCKTIME" --address)
echo "channel address: $CHANNEL"

read -r FUNDING_HEX FUNDING_TXID FUNDING_VOUT < <(
    ./test/mkfunding "$CHANNEL" "$ALICE_ADDR" "$CAPACITY")
printf '%s' "$FUNDING_HEX" > "$WORK/funding.hex"
echo "funding: $FUNDING_TXID:$FUNDING_VOUT"

./bob --wif "$BOB_WIF" --peer-pubkey "$ALICE_PUB" --locktime "$LOCKTIME" \
      --funding "$FUNDING_TXID:$FUNDING_VOUT" --capacity "$CAPACITY" \
      --listen "127.0.0.1:$PORT" --once > "$WORK/bob.log" 2>&1 &
BOB_PID=$!

for _ in $(seq 1 50); do
    grep -q "listening" "$WORK/bob.log" 2>/dev/null && break
    sleep 0.1
done

./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
        --funding "$FUNDING_TXID:$FUNDING_VOUT" --funding-tx "@$WORK/funding.hex" \
        --capacity "$CAPACITY" --connect "127.0.0.1:$PORT" \
        --pay 5.0 --pay 12.5 --pay 30.0 --close | tee "$WORK/alice.log"

wait "$BOB_PID" || true
BOB_PID=

echo
echo "--- bob ---"
cat "$WORK/bob.log"

grep -q "accepted 3000000000 koinu" "$WORK/bob.log" || {
    echo "FAIL: bob did not accept the final payment" >&2; exit 1; }
grep -q "closing transaction" "$WORK/alice.log" || {
    echo "FAIL: alice did not get a closing transaction" >&2; exit 1; }
echo "loopback ok"
