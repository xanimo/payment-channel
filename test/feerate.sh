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
got=$(fee_for --feerate-cmd 'printf "0.02000000\n"')
[ "$got" = "0.00800000 DOGE" ] && say "--feerate-cmd 0.02 -> 0.008" yes || { say "--feerate-cmd 0.02" "$got"; fail=1; }

# a rate that prices under the floor is lifted to it
got=$(fee_for --feerate 0.0001)
[ "$got" = "0.00400000 DOGE" ] && say "sub-floor rate clamps to floor" yes || { say "sub-floor rate" "$got"; fail=1; }

# estimatefee's -1 (too little data) falls back to the floor
out=$(./alice --wif "@$WORK/awif" --peer-pubkey "$BPUB" --locktime 700 --regtest \
        --funding-tx "@$WORK/fund.hex" --refund --feerate-cmd 'printf -- "-1.00000000\n"' 2>&1)
if printf '%s' "$out" | grep -q "live feerate unavailable" \
   && printf '%s' "$out" | grep -q "^alice: fee 0.00400000 DOGE"; then
    say "estimatefee -1 falls back to floor" yes
else
    say "estimatefee -1" "$out"; fail=1
fi

# a failing command falls back the same way
got=$(fee_for --feerate-cmd 'exit 1')
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
        --funding-tx "@$WORK/fund.hex" --refund --feerate 0.5 --feerate-cmd 'printf "0.1\n"' 2>&1 \
        | grep -q "one of --feerate"; then
    say "--feerate with --feerate-cmd is refused" yes
else
    say "--feerate with --feerate-cmd" "not refused"; fail=1
fi

[ "$fail" = 0 ] || { echo "feerate FAILED" >&2; exit 1; }
echo "feerate ok"
