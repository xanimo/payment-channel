#!/usr/bin/env bash
# --feerate/--feerate-cmd size Alice's fee from a live rate instead of the flat
# --fee. The fee is proportional to PC_TYPICAL_TX_BYTES (400) and never drops
# under the policy floor, pc_min_fee(400,0) = 0.00400000 DOGE. estimatefee
# prints -1 when it has too little history, and that, a failing command or a
# non-positive value all fall back to the floor rather than block the close.
set -eu

cd "$(dirname "$0")/.."
[ -x ./alice ] && [ -x ./test/mkfunding ] || { echo "build first: make check" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
fail=0
say() { printf "  %-52s %s\n" "$1" "$2"; }

# --feerate-cmd is run through pc_run_backend: execvp, no shell. A stub file is
# what an operator would really point it at, and it is the only thing that
# works now that `printf "..."` is not re-parsed by sh.
rate_stub() {                    # rate_stub NAME TEXT [EXIT]
    printf '#!/usr/bin/env bash\nprintf "%%s\\n" "%s"\nexit %s\n' "$2" "${3:-0}" \
        > "$WORK/$1"
    chmod +x "$WORK/$1"
}
rate_stub r002  0.02000000
rate_stub rneg  -1.00000000
rate_stub r1250 1250.0
rate_stub r01   0.1
rate_stub rfail 0 1
rate_stub rlong  0.000000000000000000000000000000000000000000000001
printf '#!/usr/bin/env bash\nsleep 60\n' > "$WORK/rhang"; chmod +x "$WORK/rhang"

# two distinct regtest keys: one signer, one to stand in as the peer
read -r AWIF _ < <(./test/mkfunding --keys --regtest)
read -r _ ADEST < <(./test/mkfunding --keys --regtest)
read -r BWIF _ < <(./test/mkfunding --keys --regtest)
printf '%s' "$AWIF" > "$WORK/awif"; chmod 600 "$WORK/awif"
printf '%s' "$BWIF" > "$WORK/bwif"; chmod 600 "$WORK/bwif"
BPUB=$(./alice --wif "@$WORK/bwif" --regtest --pubkey)
CADDR=$(./alice --wif "@$WORK/awif" --peer-pubkey "$BPUB" --locktime 700 --regtest --address)
./test/mkfunding "$CADDR" "$ADEST" 100.0 | awk '{print $1}' > "$WORK/fund.hex"

# the fee alice announces on stderr, in DOGE, for a --refund built under $@
fee_for() {
    ./alice --wif "@$WORK/awif" --peer-pubkey "$BPUB" --locktime 700 --regtest \
        --funding-tx "@$WORK/fund.hex" --refund "$@" 2>&1 \
        | sed -n 's/^alice: fee //p'
}

echo "feerate sizing:"

# 0.5 DOGE/kB over 400 bytes is 0.2 DOGE, well over the floor
got=$(fee_for --feerate 0.5)
[ "$got" = "0.20000000 DOGE" ] && say "--feerate 0.5 -> 0.2" yes || { say "--feerate 0.5" "$got"; fail=1; }

# 0.02 DOGE/kB is 0.008, still over the floor
got=$(fee_for --feerate-cmd "$WORK/r002")
[ "$got" = "0.00800000 DOGE" ] && say "--feerate-cmd 0.02 -> 0.008" yes || { say "--feerate-cmd 0.02" "$got"; fail=1; }

# a rate that prices under the floor is lifted to it
got=$(fee_for --feerate 0.0001)
[ "$got" = "0.00400000 DOGE" ] && say "sub-floor rate clamps to floor" yes || { say "sub-floor rate" "$got"; fail=1; }

# estimatefee's -1 (too little data) falls back to the floor
out=$(./alice --wif "@$WORK/awif" --peer-pubkey "$BPUB" --locktime 700 --regtest \
        --funding-tx "@$WORK/fund.hex" --refund --feerate-cmd "$WORK/rneg" 2>&1)
if printf '%s' "$out" | grep -q "live feerate unavailable" \
   && printf '%s' "$out" | grep -q "^alice: fee 0.00400000 DOGE"; then
    say "estimatefee -1 falls back to floor" yes
else
    say "estimatefee -1" "$out"; fail=1
fi

# a failing command falls back the same way
got=$(fee_for --feerate-cmd "$WORK/rfail")
[ "$got" = "0.00400000 DOGE" ] && say "failing --feerate-cmd falls back" yes || { say "failing --feerate-cmd" "$got"; fail=1; }

# --fee and --feerate are the same knob twice, so passing both is refused
if ./alice --wif "@$WORK/awif" --peer-pubkey "$BPUB" --locktime 700 --regtest \
        --funding-tx "@$WORK/fund.hex" --refund --fee 1.0 --feerate 0.5 2>&1 \
        | grep -q "pass one"; then
    say "--fee with --feerate is refused" yes
else
    say "--fee with --feerate" "not refused"; fail=1
fi

# --feerate with --feerate-cmd is refused too
if ./alice --wif "@$WORK/awif" --peer-pubkey "$BPUB" --locktime 700 --regtest \
        --funding-tx "@$WORK/fund.hex" --refund --feerate 0.5 --feerate-cmd "$WORK/r01" 2>&1 \
        | grep -q "one of --feerate"; then
    say "--feerate with --feerate-cmd is refused" yes
else
    say "--feerate with --feerate-cmd" "not refused"; fail=1
fi

echo "fee ceiling:"

# the fee a run refuses with, or its stderr, whichever it produced
try_fee() {
    ./alice --wif "@$WORK/awif" --peer-pubkey "$BPUB" --locktime 700 --regtest \
        --funding-tx "@$WORK/fund.hex" --refund "$@" 2>&1
}

# DEFAULT_TRANSACTION_MAXFEE is 100 DOGE, so a flat 500 is refused before the
# transaction is built at all.
try_fee --fee 500 | grep -q "over the 100.00000000 a node will relay" &&
    say "--fee over the cap is refused" yes ||
    { say "--fee 500" "$(try_fee --fee 500 | head -1)"; fail=1; }

# 1250 DOGE/kB over 400 bytes prices at exactly 500 DOGE. A backend answering
# in the wrong units is the case this exists for: the number is not the
# operator's, and nothing else would have caught it.
try_fee --feerate 1250 | grep -q "over the 100.00000000 a node will relay" &&
    say "a wild --feerate is refused not paid" yes ||
    { say "--feerate 1250" "$(try_fee --feerate 1250 | head -1)"; fail=1; }

try_fee --feerate-cmd "$WORK/r1250" | grep -q "a node will relay" &&
    say "and the same through --feerate-cmd" yes ||
    { say "--feerate-cmd 1250" "$(try_fee --feerate-cmd "$WORK/r1250" | head -1)"; fail=1; }

# right at the cap is allowed: the check is > not >=
try_fee --fee 100 | grep -q "a node will relay" &&
    { say "--fee exactly at the cap" "refused, should pass"; fail=1; } ||
    say "a fee exactly at the cap is allowed" yes

# --max-fee is the allowhighfees equivalent. It stops being the fee that is
# refused; this channel only holds 100 so the run still fails later, which is a
# different message and not this check's business.
try_fee --fee 500 --max-fee 600 | grep -q "a node will relay" &&
    { say "--max-fee did not raise the ceiling" no; fail=1; } ||
    say "--max-fee raises the ceiling" yes

echo "fee share warning:"

# The band the cap does not cover. This channel holds 100 DOGE, so a backend
# answering 50 DOGE/kB prices 20 DOGE over 400 bytes: legal, relayable, under
# the 100 cap, and a fifth of the channel. Reported, never refused.
out=$(try_fee --feerate 50)
printf '%s' "$out" | grep -q "is 20% of this 100.00000000 DOGE channel" &&
    say "a fee that is a fifth of the channel is reported" yes ||
    { say "--feerate 50 share" "$(printf '%s' "$out" | grep 'alice:' | head -1)"; fail=1; }

# reporting is not refusing: the refund still gets built
printf '%s' "$out" | grep -q "refund transaction, spendable from block" &&
    say "and the refund is still built, not blocked" yes ||
    { say "refund after warning" "not built"; fail=1; }

# an ordinary fee says nothing at all
try_fee --fee 1.0 | grep -q "of this" &&
    { say "an ordinary fee warns" "it should not"; fail=1; } ||
    say "an ordinary fee is silent" yes

# the threshold is 10%, so just under it stays quiet
try_fee --fee 9.0 | grep -q "of this" &&
    { say "9% warned" "threshold is wrong"; fail=1; } ||
    say "just under the threshold is silent" yes

try_fee --fee 10.0 | grep -q "is 10% of this" &&
    say "and exactly at it reports" yes ||
    { say "10% did not warn" "$(try_fee --fee 10.0 | grep 'alice:' | head -1)"; fail=1; }

echo "a rate that does not fit:"

# per_kb * 400 wraps a uint64 near zero, which used to come out as 1 koinu,
# get lifted to the policy floor and sail under the ceiling that exists for
# exactly this. Saturating sends it into the refusal instead.
try_fee --feerate 461168601.84273880 | grep -q "a node will relay" &&
    say "a feerate that overflows the fee is refused" yes ||
    { say "overflowing feerate" "$(try_fee --feerate 461168601.84273880 | grep alice: | head -1)"; fail=1; }

try_fee --feerate 922337203.68547759 | grep -q "a node will relay" &&
    say "and so is the next one up" yes ||
    { say "overflowing feerate 2" "$(try_fee --feerate 922337203.68547759 | grep alice: | head -1)"; fail=1; }

# a token longer than the buffer is refused, not cut: a truncated amount is a
# different number rather than a shorter one
got=$(fee_for --feerate-cmd "$WORK/rlong")
[ "$got" = "0.00400000 DOGE" ] &&
    say "an over-long rate is refused, not truncated" yes ||
    { say "over-long rate" "$got"; fail=1; }

# a backend that never answers is killed rather than waited on, which is the
# half that mattered: --refund reaches here and its locktime does not pause
start=$(date +%s)
got=$(fee_for --feerate-cmd "$WORK/rhang")
took=$(( $(date +%s) - start ))
[ "$got" = "0.00400000 DOGE" ] && [ "$took" -lt 20 ] &&
    say "a hanging backend is killed, not waited on (${took}s)" yes ||
    { say "hanging backend" "$got after ${took}s"; fail=1; }

[ "$fail" = 0 ] || { echo "feerate FAILED" >&2; exit 1; }
echo "feerate ok"
