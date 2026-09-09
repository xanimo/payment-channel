#!/usr/bin/env bash
# The key is pinned in RAM so it never reaches swap. mlock is best effort but
# loud: silent when it works, a warning when a low RLIMIT_MEMLOCK stops it, so an
# operator who thinks the key is protected and is not gets told. The key still
# works either way, since refusing to run would be worse than a warned-about
# swap risk. Core-dump suppression is set the same place but cannot be observed
# from outside the process, so it is verified by reading main, not here.
set -eu

cd "$(dirname "$0")/.."
[ -x ./bob ] && [ -x ./test/mkfunding ] || { echo "build first: make check" >&2; exit 1; }

read -r WIF _ < <(./test/mkfunding --keys)
fail=0
say() { printf "  %-48s %s\n" "$1" "$2"; }

echo "key stays off swap:"

# mlock succeeds under a normal limit, so nothing is printed and the pubkey comes
# back clean.
out=$(./bob --wif "$WIF" --pubkey 2>&1)
if ! printf '%s' "$out" | grep -qi mlock && [ "${#out}" = 66 ]; then
    say "no warning when the key locks" "yes"
else
    say "no warning when the key locks" "$out"; fail=1
fi

# with the lock budget at zero, mlock cannot pin the page: the warning fires and
# the key still decodes, since a warned swap risk beats refusing to start.
out=$(ulimit -l 0; ./bob --wif "$WIF" --pubkey 2>&1)
if printf '%s' "$out" | grep -qi "mlock of secret failed" \
   && printf '%s' "$out" | grep -q '^02\|^03'; then
    say "a failed lock warns but still runs" "yes"
else
    say "a failed lock warns but still runs" "$out"; fail=1
fi

[ "$fail" = 0 ] || { echo "keyguard FAILED" >&2; exit 1; }
echo "keyguard ok"
