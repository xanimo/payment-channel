#!/usr/bin/env bash
# Alice reads the closing transaction before she prints it.
#
# Bob cannot forge one: it carries her signature over a digest he cannot produce
# without her key, so a tampered close is not a way to take her money. It is
# still the one artifact she takes from him and puts in front of a user as an
# instruction to broadcast, and she holds everything needed to check it. This
# proves she does, by putting a proxy between the two that passes the whole
# session through untouched and corrupts only the final close.
set -eu

cd "$(dirname "$0")/.."
PORT=${PORT:-19899}
PROXY=${PROXY:-19900}
LOCKTIME=${LOCKTIME:-300000}
for b in alice bob test/mkfunding; do
    [ -x "$b" ] || { echo "build first: make check" >&2; exit 1; }
done
command -v python3 >/dev/null || { echo "closecheck: needs python3" >&2; exit 0; }

WORK=$(mktemp -d)
BOB_PID=; PROXY_PID=
trap 'rm -rf "$WORK"
      [ -n "$BOB_PID" ] && kill "$BOB_PID" 2>/dev/null
      [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
      true' EXIT
fail=0
say() { printf "  %-52s %s\n" "$1" "$2"; }

read -r ALICE_WIF ALICE_ADDR < <(./test/mkfunding --keys)
read -r BOB_WIF   _          < <(./test/mkfunding --keys)
BOB_PUB=$(./bob --wif "$BOB_WIF" --pubkey)
CHANNEL=$(./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" --address)
read -r FUNDING_HEX _ _ < <(./test/mkfunding "$CHANNEL" "$ALICE_ADDR" 100.0)
printf '%s' "$FUNDING_HEX" > "$WORK/funding.hex"

# A proxy that is honest about everything except the close. MODE=flip changes a
# byte of the transaction, MODE=swap replaces it with the funding transaction,
# which parses as a transaction and is not this channel's close.
cat > "$WORK/proxy.py" <<'PROXY'
import os, socket, sys, threading
listen, upstream, mode = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
funding = open(sys.argv[4]).read().strip()

def tamper(line):
    if b'"type":"close"' not in line:
        return line
    import re
    m = re.search(rb'"psbt":"([0-9a-fA-F]*)"', line)
    if not m or not m.group(1):
        return line
    tx = m.group(1).decode()
    if mode == "swap":
        new = funding
    else:
        c = tx[-6]
        new = tx[:-6] + ("a" if c != "a" else "b") + tx[-5:]
    return line[:m.start(1)] + new.encode() + line[m.end(1):]

def pump(src, dst, fn):
    try:
        f = src.makefile("rb")
        for line in f:
            dst.sendall(fn(line))
    except Exception:
        pass
    finally:
        try: dst.shutdown(socket.SHUT_WR)
        except Exception: pass

s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", listen)); s.listen(1)
print("ready", flush=True)
a, _ = s.accept()
b = socket.create_connection(("127.0.0.1", upstream))
t = threading.Thread(target=pump, args=(a, b, lambda l: l)); t.start()
pump(b, a, tamper)
t.join()
PROXY

run_case() {          # run_case MODE LABEL
    mkdir -p "$WORK/state-$1"
    ./bob --wif "$BOB_WIF" --listen "127.0.0.1:$PORT" --trust-peer --once \
          --height 1000 --min-slack 100 --state "$WORK/state-$1" \
          --price 5.0 > "$WORK/bob-$1.log" 2>&1 &
    BOB_PID=$!
    for _ in $(seq 1 100); do grep -q listening "$WORK/bob-$1.log" 2>/dev/null && break; sleep 0.1; done

    python3 "$WORK/proxy.py" "$PROXY" "$PORT" "$1" "$WORK/funding.hex" \
        > "$WORK/proxy-$1.log" 2>&1 &
    PROXY_PID=$!
    for _ in $(seq 1 100); do grep -q ready "$WORK/proxy-$1.log" 2>/dev/null && break; sleep 0.1; done

    ./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
            --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$PROXY" \
            --max 5.0 --close > "$WORK/alice-$1.log" 2>&1 || true
    wait "$BOB_PID" 2>/dev/null || true; BOB_PID=
    kill "$PROXY_PID" 2>/dev/null || true; wait "$PROXY_PID" 2>/dev/null || true; PROXY_PID=
}

echo "alice reads the close before she prints it:"

run_case flip
grep -q "does not check out" "$WORK/alice-flip.log" \
    && say "a tampered signature is refused" yes \
    || { say "tampered close" "$(grep -i alice: "$WORK/alice-flip.log" | head -1)"; fail=1; }

grep -q "closing transaction, either side" "$WORK/alice-flip.log" \
    && { say "and it is not printed as an instruction" no; fail=1; } \
    || say "and it is not printed as an instruction" yes

grep -q "refund is still there at locktime" "$WORK/alice-flip.log" \
    && say "and she is told the refund still stands" yes \
    || { say "no mention of the refund" "no"; fail=1; }

run_case swap
grep -q "does not check out" "$WORK/alice-swap.log" \
    && say "a different transaction entirely is refused" yes \
    || { say "swapped close" "$(grep -i alice: "$WORK/alice-swap.log" | head -1)"; fail=1; }

# and the honest path still prints one, so this is not refusing everything
mkdir -p "$WORK/state-ok"
./bob --wif "$BOB_WIF" --listen "127.0.0.1:$((PORT+1))" --trust-peer --once \
      --height 1000 --min-slack 100 --state "$WORK/state-ok" \
      --price 5.0 > "$WORK/bob-ok.log" 2>&1 &
BOB_PID=$!
for _ in $(seq 1 100); do grep -q listening "$WORK/bob-ok.log" 2>/dev/null && break; sleep 0.1; done
./alice --wif "$ALICE_WIF" --peer-pubkey "$BOB_PUB" --locktime "$LOCKTIME" \
        --funding-tx "@$WORK/funding.hex" --connect "127.0.0.1:$((PORT+1))" \
        --max 5.0 --close > "$WORK/alice-ok.log" 2>&1 || true
wait "$BOB_PID" 2>/dev/null || true; BOB_PID=
grep -q "closing transaction, either side" "$WORK/alice-ok.log" \
    && say "an untampered close is still printed" yes \
    || { say "honest close" "$(grep -i alice: "$WORK/alice-ok.log" | head -1)"; fail=1; }

[ "$fail" = 0 ] || { echo "closecheck FAILED" >&2; exit 1; }
echo "closecheck ok"
