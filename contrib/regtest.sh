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

# regtest shares testnet's p2sh prefix but not its p2pkh one (0x6f against
# 0x71), so --testnet here would print addresses this node does not recognise
# even though the scripts are identical
NET=--regtest

read -r ALICE_WIF ALICE_ADDR < <(./test/mkfunding --keys --regtest)
read -r BOB_WIF   BOB_ADDR   < <(./test/mkfunding --keys --regtest)

ALICE_PUB=$(./alice $NET --wif "$ALICE_WIF" --pubkey)
BOB_PUB=$(./bob    $NET --wif "$BOB_WIF"    --pubkey)

# Only Alice derives the address now. Bob is told nothing about the channel and
# reads it back out of the opening PSBT, refusing any script that does not name
# his own key, so there is no out-of-band address left to compare.
LOCKTIME=$(( $("${RPC[@]}" getblockcount) + 500 ))
CHANNEL=$(./alice $NET --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" \
                       --locktime "$LOCKTIME" --address)
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

# Bob prices three orders and invoices for them one at a time. They are what
# each order costs, so the cumulative totals are 5, 12.5 and 30. He measures the
# locktime against the height he is given, because he cannot see the chain.
HEIGHT=$("${RPC[@]}" getblockcount)
# --trust-peer: the funding here is one this script just broadcast and mined,
# so there is nothing for a backend to tell Bob that the node has not already
# been asked. The --confirm-cmd path is exercised further down against KW.
./bob $NET --wif "$BOB_WIF" --listen "127.0.0.1:$PORT" --once --trust-peer \
           --height "$HEIGHT" --min-slack 100 \
           --price 5.0 --price 7.5 --price 17.5 > "$WORK/bob.log" 2>&1 &
BOB_PID=$!

for _ in $(seq 1 50); do
    grep -q listening "$WORK/bob.log" 2>/dev/null && break
    sleep 0.1
done

./alice $NET --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
             --funding-tx "@$WORK/funding.hex" --fee "$FEE" \
             --max "$CAPACITY" --connect "127.0.0.1:$PORT" \
             --close | tee "$WORK/alice.log"

wait "$BOB_PID" || true
BOB_PID=

# she is given the transaction, not the outpoint, so check she picked the same
# output of it that the node reports
grep -q "funding  $TXID:$VOUT " "$WORK/alice.log" || {
    echo "FAIL: alice derived a different funding output" >&2
    cat "$WORK/bob.log" >&2; exit 1; }

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
echo "bob paid $PAID DOGE, expected 30"
[ "$PAID" = "30.0" ] || { echo "FAIL: bob was not paid 30" >&2; exit 1; }

# The cooperative close is one of two transactions this scheme produces. The
# other is Alice's unilateral refund through the CLTV branch, and it is the one
# that gets her money back when Bob stops answering. "should work" is not the
# standard to hold a recovery path to, so broadcast one.
echo
R_LOCKTIME=$(( $("${RPC[@]}" getblockcount) + 5 ))
R_CHANNEL=$(./alice $NET --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" \
                         --locktime "$R_LOCKTIME" --address)
echo "refund   channel $R_CHANNEL  locktime $R_LOCKTIME"
R_TXID=$("${RPC[@]}" sendtoaddress "$R_CHANNEL" "$CAPACITY")
"${RPC[@]}" generate 6 >/dev/null          # confirm it, and pass the locktime
"${RPC[@]}" getrawtransaction "$R_TXID" > "$WORK/refund_funding.hex"

REFUND=$(./alice $NET --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" \
                      --locktime "$R_LOCKTIME" --fee "$FEE" --refund \
                      --funding-tx "@$WORK/refund_funding.hex" | tail -1)
[ -n "$REFUND" ] || { echo "FAIL: no refund transaction" >&2; exit 1; }

R_SENT=$("${RPC[@]}" sendrawtransaction "$REFUND") || {
    echo "FAIL: the node would not accept the refund" >&2; exit 1; }
"${RPC[@]}" generate 1 >/dev/null
R_CONFS=$("${RPC[@]}" getrawtransaction "$R_SENT" 1 | python3 -c \
          'import json,sys; print(json.load(sys.stdin).get("confirmations",0))')
echo "refund   $R_SENT  confirmations $R_CONFS"
[ "$R_CONFS" -ge 1 ] || { echo "FAIL: refund did not confirm" >&2; exit 1; }

R_PAID=$("${RPC[@]}" getrawtransaction "$R_SENT" 1 | python3 -c '
import json,sys
tx=json.load(sys.stdin)
want=sys.argv[1]
t=0
for o in tx["vout"]:
    spk=o.get("scriptPubKey",{})
    if want in spk.get("addresses",[]) or spk.get("address")==want:
        t+=o["value"]
print(t)
' "$ALICE_ADDR")
echo "refund   returned $R_PAID DOGE to alice, expected 99"
[ "$R_PAID" = "99.0" ] || { echo "FAIL: refund did not return the balance" >&2; exit 1; }

# ── the funding check, against the chain rather than against alice ──────────
#
# Everything above proves the transactions are valid. This proves the one thing
# bob cannot check for himself: that the funding output alice described is
# actually there, buried, unspent and worth what she said. Set KW to a built
# koinu binary to run it; without one the confirmation path is only ever tested
# against a stub, and a stub written from the same reading as the code agrees
# with the code and with nothing else. That is how --confirm-cmd shipped unable
# to invoke the tool it was built for.
if [ -n "${KW:-}" ]; then
    [ -x "$KW" ] || { echo "KW=$KW is not executable" >&2; exit 1; }
    KWARGS="$KW --regtest outpoint --node 127.0.0.1 --port ${P2P:-18444} --spv --headers $WORK/hdrs"
    KWSEND="$KW --regtest send --node 127.0.0.1 --port ${P2P:-18444}"

    confirm_bob() {
        rm -rf "$WORK/cstate"; mkdir -p "$WORK/cstate"
        "${RPC[@]}" getblockcount > "$WORK/cheight"
        ./bob $NET --wif "$BOB_WIF" --listen "127.0.0.1:$((PORT + 2))" --once \
                   --min-slack 100 --height-file "$WORK/cheight" \
                   --state "$WORK/cstate" --confirm-cmd "$KWARGS" \
                   --broadcast-cmd "$KWSEND" \
                   --min-depth "${MIN_DEPTH:-6}" --price 5.0 > "$WORK/cbob.log" 2>&1 &
        CBOB=$!
        for _ in $(seq 1 80); do
            grep -q listening "$WORK/cbob.log" 2>/dev/null && break
            sleep 0.1
        done
        ./alice $NET --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$1" \
                     --funding-tx "@$2" --connect "127.0.0.1:$((PORT + 2))" \
                     --max "$CAPACITY" > "$WORK/calice.log" 2>&1 || true
        kill "$CBOB" 2>/dev/null || true
        wait "$CBOB" 2>/dev/null || true
    }

    # a fresh, buried funding output: it opens
    C_LOCKTIME=$(( $("${RPC[@]}" getblockcount) + 500 ))
    C_CHANNEL=$(./alice $NET --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" \
                             --locktime "$C_LOCKTIME" --address)
    C_TXID=$("${RPC[@]}" sendtoaddress "$C_CHANNEL" "$CAPACITY")

    # before it is buried, the same channel is refused
    "${RPC[@]}" getrawtransaction "$C_TXID" > "$WORK/cfunding.hex"
    confirm_bob "$C_LOCKTIME" "$WORK/cfunding.hex"
    grep -q "unconfirmed or spent" "$WORK/cbob.log" \
        || { echo "FAIL: an unconfirmed funding output was accepted" >&2; exit 1; }
    echo "confirm  unconfirmed funding refused"

    "${RPC[@]}" generate 6 >/dev/null
    confirm_bob "$C_LOCKTIME" "$WORK/cfunding.hex"
    grep -q "confirmed to at least" "$WORK/cbob.log" \
        || { echo "FAIL: a buried funding output was refused" >&2;
             tail -3 "$WORK/cbob.log" >&2; exit 1; }
    echo "confirm  buried funding accepted"

    # and the outpoint the close already spent is refused, with the state
    # directory emptied so only the chain can be what refuses it
    confirm_bob "$LOCKTIME" "$WORK/funding.hex"
    grep -q "unconfirmed or spent" "$WORK/cbob.log" \
        || { echo "FAIL: a spent funding output was accepted" >&2; exit 1; }
    echo "confirm  spent funding refused"

    # and bob hands the close to the chain himself rather than printing it for
    # someone to relay, which is the window alice's refund is racing
    B_LOCKTIME=$(( $("${RPC[@]}" getblockcount) + 500 ))
    B_CHANNEL=$(./alice $NET --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" \
                             --locktime "$B_LOCKTIME" --address)
    B_TXID=$("${RPC[@]}" sendtoaddress "$B_CHANNEL" "$CAPACITY")
    "${RPC[@]}" generate 6 >/dev/null
    "${RPC[@]}" getrawtransaction "$B_TXID" > "$WORK/bfunding.hex"
    rm -rf "$WORK/cstate"; mkdir -p "$WORK/cstate"
    "${RPC[@]}" getblockcount > "$WORK/cheight"
    ./bob $NET --wif "$BOB_WIF" --listen "127.0.0.1:$((PORT + 3))" --once \
               --min-slack 100 --height-file "$WORK/cheight" \
               --state "$WORK/cstate" --confirm-cmd "$KWARGS" \
               --broadcast-cmd "$KWSEND" --min-depth "${MIN_DEPTH:-6}" \
               --price 5.0 > "$WORK/bbob.log" 2>&1 &
    BBOB=$!
    for _ in $(seq 1 80); do
        grep -q listening "$WORK/bbob.log" 2>/dev/null && break; sleep 0.1
    done
    ./alice $NET --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$B_LOCKTIME" \
                 --funding-tx "@$WORK/bfunding.hex" --fee "$FEE" --max "$CAPACITY" \
                 --connect "127.0.0.1:$((PORT + 3))" --close > "$WORK/balice.log" 2>&1 || true
    for _ in $(seq 1 60); do
        grep -q "broadcast:" "$WORK/bbob.log" 2>/dev/null && break; sleep 0.5
    done
    kill "$BBOB" 2>/dev/null || true; wait "$BBOB" 2>/dev/null || true
    B_SENT=$(grep -oE "broadcast: [0-9a-f]{64}" "$WORK/bbob.log" | awk '{print $2}')
    [ -n "$B_SENT" ] || { echo "FAIL: bob did not broadcast the close" >&2
                          tail -3 "$WORK/bbob.log" >&2; exit 1; }
    "${RPC[@]}" generate 1 >/dev/null
    B_CONFS=$("${RPC[@]}" getrawtransaction "$B_SENT" 1 | python3 -c \
              'import json,sys; print(json.load(sys.stdin).get("confirmations",0))')
    [ "$B_CONFS" -ge 1 ] || { echo "FAIL: bob's broadcast did not confirm" >&2; exit 1; }
    echo "confirm  bob broadcast the close himself, $B_SENT confirmed"

    # And the payment nobody closed on. This is the path that had no coverage
    # here, and verifying it by hand found two bugs: a channel rebuilt from a
    # state file that only stores its parts, and a backend failure being read
    # as "the output is gone" and retiring the payment.
    S_LOCKTIME=$(( $("${RPC[@]}" getblockcount) + 500 ))
    S_CHANNEL=$(./alice $NET --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" \
                             --locktime "$S_LOCKTIME" --address)
    S_TXID=$("${RPC[@]}" sendtoaddress "$S_CHANNEL" "$CAPACITY")
    "${RPC[@]}" generate 6 >/dev/null
    "${RPC[@]}" getrawtransaction "$S_TXID" > "$WORK/sfunding.hex"
    rm -rf "$WORK/sstate"; mkdir -p "$WORK/sstate"
    "${RPC[@]}" getblockcount > "$WORK/sheight"

    ./bob $NET --wif "$BOB_WIF" --listen "127.0.0.1:$((PORT + 4))" --once \
               --min-slack 100 --height-file "$WORK/sheight" \
               --state "$WORK/sstate" --confirm-cmd "$KWARGS" \
               --min-depth "${MIN_DEPTH:-6}" --price 5.0 > "$WORK/sbob.log" 2>&1 &
    SBOB=$!
    for _ in $(seq 1 80); do
        grep -q listening "$WORK/sbob.log" 2>/dev/null && break; sleep 0.1
    done
    # no --close: alice pays and walks away, which is the whole point
    ./alice $NET --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$S_LOCKTIME" \
                 --funding-tx "@$WORK/sfunding.hex" --fee "$FEE" --max "$CAPACITY" \
                 --connect "127.0.0.1:$((PORT + 4))" > "$WORK/salice.log" 2>&1 || true
    kill "$SBOB" 2>/dev/null || true; wait "$SBOB" 2>/dev/null || true

    grep -q "^paid " "$WORK/sstate"/*.channel \
        || { echo "FAIL: nothing was recorded for the unclosed channel" >&2; exit 1; }

    SWEEP() {
        ./bob $NET --sweep --state "$WORK/sstate" --height-file "$WORK/sheight" \
              --broadcast-cmd "$KWSEND" --confirm-cmd "$KWARGS" \
              --min-depth 1 --sweep-margin "$1" 2>&1
    }

    # far from the locktime: leave it alone
    SWEEP 50 | grep -q "0 broadcast" \
        || { echo "FAIL: swept a channel with time left" >&2; exit 1; }

    # a backend that cannot answer must change nothing
    ./bob $NET --sweep --state "$WORK/sstate" --height-file "$WORK/sheight" \
          --broadcast-cmd "$KWSEND" --confirm-cmd /bin/false \
          --sweep-margin 600 > "$WORK/sweep0.log" 2>&1 || true
    grep -q "leaving it for the next pass" "$WORK/sweep0.log" \
        || { echo "FAIL: a broken backend did not leave the channel alone" >&2; exit 1; }
    grep -q "^closed 0" "$WORK/sstate"/*.channel \
        || { echo "FAIL: a broken backend retired the channel" >&2; exit 1; }

    # inside the margin: broadcast, but record it as sent rather than finished
    SWEEP 600 | grep -q "1 broadcast" \
        || { echo "FAIL: the sweep did not broadcast" >&2; exit 1; }
    grep -q "^sent 1" "$WORK/sstate"/*.channel \
        || { echo "FAIL: the sweep did not record the send" >&2; exit 1; }
    grep -q "^closed 0" "$WORK/sstate"/*.channel \
        || { echo "FAIL: the sweep retired on a send that was not confirmed" >&2; exit 1; }
    echo "confirm  sweep broadcast an unclosed payment without retiring it"

    # once it confirms, the outpoint is spent and that is what closes it
    "${RPC[@]}" generate 1 >/dev/null
    "${RPC[@]}" getblockcount > "$WORK/sheight"
    SWEEP 600 | grep -q "1 confirmed" \
        || { echo "FAIL: a confirmed close did not retire the channel" >&2; exit 1; }
    grep -q "^closed 1" "$WORK/sstate"/*.channel \
        || { echo "FAIL: the channel was not closed after confirming" >&2; exit 1; }
    echo "confirm  and retired it once the chain showed the outpoint spent"
else
    # Loud, not silent. The confirmation path is the only thing standing
    # between bob and a funding output that was never broadcast, and a stub
    # cannot check that the question asked of the backend is the right one.
    echo "confirm  SKIPPED: set KW to a built koinu binary to check the"
    echo "confirm           funding path against a real chain"
fi

echo "regtest ok"
