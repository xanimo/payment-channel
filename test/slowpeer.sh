#!/usr/bin/env bash
# A peer that is slow rather than malformed.
#
# fuzz_envelope mutates bytes, so everything it finds is a parse that goes
# wrong. Nothing tested a peer whose bytes are fine and never end: connect and
# say nothing, send half a line and stop, or dribble a byte at a time forever.
# wire.c has a per-read budget and a whole-line deadline for exactly this and
# neither had ever been shown to fire.
#
# The dribble case has to outlast the line deadline to prove anything, so it
# costs PC_WIRE_TIMEOUT_SEC. It is skipped unless SLOW=1.
set -eu

cd "$(dirname "$0")/.."
PORT=${PORT:-19878}
IO_SEC=5              # PC_WIRE_IO_SEC
LINE_SEC=30           # PC_WIRE_TIMEOUT_SEC

for b in bob test/mkfunding; do
    [ -x "$b" ] || { echo "build first: make check" >&2; exit 1; }
done
command -v python3 >/dev/null || { echo "SKIP: needs python3" >&2; exit 0; }

WORK=$(mktemp -d)
BOB_PID=
trap 'rm -rf "$WORK"; [ -n "$BOB_PID" ] && kill "$BOB_PID" 2>/dev/null || true' EXIT

read -r BOB_WIF _ < <(./test/mkfunding --keys)

start_bob() {
    ./bob --wif "$BOB_WIF" --listen "127.0.0.1:$PORT" \
          --height 1000 --min-slack 100 --price 5.0 > "$WORK/bob.log" 2>&1 &
    BOB_PID=$!
    for _ in $(seq 1 100); do
        grep -q "listening" "$WORK/bob.log" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "FAIL: bob never listened" >&2; exit 1
}

# Returns how long bob took to close on us. The assertion is that he closes at
# all: a peer that holds a slot open until the operator notices is the failure,
# and it does not announce itself.
hold() {
    local mode=$1 budget=$2
    python3 - "$PORT" "$mode" "$budget" <<'PY'
import socket, sys, time
port, mode, budget = int(sys.argv[1]), sys.argv[2], float(sys.argv[3])
s = socket.create_connection(("127.0.0.1", port), timeout=budget + 10)
start = time.time()
if mode == "prefix":
    s.sendall(b'{"type":"request","ref":"')          # valid so far, no newline
elif mode == "dribble":
    pass
# Poll for the close rather than blocking on recv. Blocking here is what made
# an earlier version of this look like it dribbled while actually sending one
# byte and then going quiet, which the per-read budget caught in 5s and the
# line deadline never saw.
s.setblocking(False)
deadline = start + budget + 10
try:
    while time.time() < deadline:
        if mode == "dribble":
            try:
                s.sendall(b'a')                       # keeps every read fed
            except (BlockingIOError, OSError):
                break
        end = time.time() + (2 if mode == "dribble" else 0.25)
        while time.time() < end:
            try:
                if not s.recv(1):
                    raise ConnectionResetError
            except BlockingIOError:
                time.sleep(0.05)
except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
    pass
took = time.time() - start
print(f"{took:.1f}")
sys.exit(0 if took <= budget else 1)
PY
}

fail=0
check() {
    local name=$1 mode=$2 budget=$3
    start_bob
    if took=$(hold "$mode" "$budget"); then
        printf "  dropped in %5ss (budget %ss)  %s\n" "$took" "$budget" "$name"
    else
        printf "  HELD OPEN past %ss              %s\n" "$budget" "$name"
        fail=1
    fi
    kill "$BOB_PID" 2>/dev/null || true
    wait "$BOB_PID" 2>/dev/null || true
    BOB_PID=
}

echo "slow peer:"
check "connects and says nothing"          silent  $((IO_SEC + 5))
check "sends a valid prefix and stops"     prefix  $((IO_SEC + 5))
if [ "${SLOW:-0}" = "1" ]; then
    check "dribbles a byte every 2 seconds" dribble $((LINE_SEC + 10))
else
    echo "  skipped (SLOW=1 to run)        dribbles a byte every 2 seconds"
fi

[ "$fail" = 0 ] || { echo "slowpeer FAILED" >&2; exit 1; }
echo "slowpeer ok"
