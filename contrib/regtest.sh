#!/usr/bin/env bash
# Drives the whole thing against a real dogecoind in regtest: funds the channel,
# confirms it, runs the payments, broadcasts the close and checks it confirmed.
#
# This is the only thing here that proves the transactions are valid. The unit
# test and the loopback test both check our own arithmetic against itself.
#
# Needs a regtest node with a funded wallet:
#   dogecoind -regtest -daemon
#   dogecoin-cli -regtest generate 200
set -euo pipefail

cd "$(dirname "$0")/.."

CLI=${CLI:-dogecoin-cli}
RPC=("$CLI" -regtest)
PORT=${PORT:-19876}
CAPACITY=${CAPACITY:-100.0}
FEE=${FEE:-1.0}

command -v "$CLI" >/dev/null || { echo "no $CLI on PATH" >&2; exit 1; }
"${RPC[@]}" getblockcount >/dev/null || { echo "no regtest node" >&2; exit 1; }

for b in alice bob test/mkfunding; do
    [ -x "$b" ] || { echo "build first: make" >&2; exit 1; }
done

WORK=$(mktemp -d)
BOB_PID=
cleanup() {
    [ -n "$BOB_PID" ] && kill "$BOB_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# regtest shares testnet's base58 prefixes, so --testnet is the right flag
NET=--testnet

read -r ALICE_WIF ALICE_ADDR < <(./test/mkfunding --keys)
read -r BOB_WIF   BOB_ADDR   < <(./test/mkfunding --keys)

ALICE_PUB=$(./alice $NET --wif "$ALICE_WIF" --pubkey)
BOB_PUB=$(./bob    $NET --wif "$BOB_WIF"    --pubkey)

# both sides must derive the same address from the same inputs
LOCKTIME=$(( $("${RPC[@]}" getblockcount) + 500 ))
CHANNEL=$(./alice $NET --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" \
                       --locktime "$LOCKTIME" --address)
CHANNEL_B=$(./bob $NET --wif "$BOB_WIF" --peer-pubkey "$ALICE_PUB" \
                       --locktime "$LOCKTIME" --address)
[ "$CHANNEL" = "$CHANNEL_B" ] || { echo "the two sides disagree on the address" >&2; exit 1; }
echo "channel  $CHANNEL  locktime $LOCKTIME"

# fund it and bury it. signing a payment against an unconfirmed funding tx is
# the one thing this scheme cannot survive.
TXID=$("${RPC[@]}" sendtoaddress "$CHANNEL" "$CAPACITY")
"${RPC[@]}" generate 6 >/dev/null
echo "funding  $TXID"

RAW=$("${RPC[@]}" getrawtransaction "$TXID")
printf '%s' "$RAW" > "$WORK/funding.hex"

VOUT=$("${RPC[@]}" getrawtransaction "$TXID" 1 | python3 -c '
import json,sys
tx=json.load(sys.stdin)
want=sys.argv[1]
for o in tx["vout"]:
    spk=o.get("scriptPubKey",{})
    if want in spk.get("addresses",[]) or spk.get("address")==want:
        print(o["n"]); break
else:
    sys.exit("channel output not found")
' "$CHANNEL")
echo "outpoint $TXID:$VOUT"

./bob $NET --wif "$BOB_WIF" --peer-pubkey "$ALICE_PUB" --locktime "$LOCKTIME" \
           --funding "$TXID:$VOUT" --capacity "$CAPACITY" \
           --listen "127.0.0.1:$PORT" --once > "$WORK/bob.log" 2>&1 &
BOB_PID=$!

for _ in $(seq 1 50); do
    grep -q listening "$WORK/bob.log" 2>/dev/null && break
    sleep 0.1
done

./alice $NET --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
             --funding "$TXID:$VOUT" --funding-tx "@$WORK/funding.hex" \
             --capacity "$CAPACITY" --fee "$FEE" \
             --connect "127.0.0.1:$PORT" \
             --pay 5.0 --pay 12.5 --pay 30.0 --close | tee "$WORK/alice.log"

wait "$BOB_PID" || true
BOB_PID=

CLOSING=$(grep -A1 "closing transaction" "$WORK/alice.log" | tail -1)
[ -n "$CLOSING" ] || { echo "no closing transaction" >&2; cat "$WORK/bob.log" >&2; exit 1; }

# the whole point: does a node accept it
CLOSE_TXID=$("${RPC[@]}" sendrawtransaction "$CLOSING")
"${RPC[@]}" generate 1 >/dev/null
CONFS=$("${RPC[@]}" getrawtransaction "$CLOSE_TXID" 1 | python3 -c \
        'import json,sys; print(json.load(sys.stdin).get("confirmations",0))')

echo
echo "close    $CLOSE_TXID  confirmations $CONFS"
[ "$CONFS" -ge 1 ] || { echo "FAIL: close did not confirm" >&2; exit 1; }

PAID=$("${RPC[@]}" getrawtransaction "$CLOSE_TXID" 1 | python3 -c '
import json,sys
tx=json.load(sys.stdin)
want=sys.argv[1]
t=0
for o in tx["vout"]:
    spk=o.get("scriptPubKey",{})
    if want in spk.get("addresses",[]) or spk.get("address")==want:
        t+=o["value"]
print(t)
' "$BOB_ADDR")
echo "bob paid $PAID DOGE"
echo "regtest ok"
