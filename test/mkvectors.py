#!/usr/bin/env python3
"""Derive sighash vectors for test/sighash_vectors.c from Dogecoin Core's own
consensus test data.

pc computes a consensus-critical digest itself (sighash_all in src/txcheck.c),
and koinu computes the same digest independently. Checking one against the other
catches drift but not a shared misreading, because both are ours. These vectors
are the outside opinion: transactions Dogecoin Core's own test suite asserts are
valid, whose signatures therefore verify only against the digest consensus
actually uses.

Run against a Dogecoin Core checkout and commit the result:

    ./test/mkvectors.py ~/source/repos/dogecoin > test/data/sighash_vectors

Not run by `make check`: the output is checked in so the test stays offline and
needs no python.

Core's sighash.json is the obvious source and cannot be used. Its 500 cases
carry random 32-bit hashTypes and pc's digest hardcodes SIGHASH_ALL, so not one
of them is in pc's domain. tx_valid.json is usable because it ships the prevout
scripts, which is what a digest needs.

tx_valid.json writes those scripts in Core's assembly notation, so this
reimplements ParseScript() from src/test/script_tests.cpp. The opcode table is
read out of Core's src/script/script.h rather than typed here, so a renamed or
renumbered opcode is picked up rather than silently wrong.

No crypto happens here. This selects transactions and the bytes a digest is
taken over; whether the digest is right is decided by secp256k1 in the C test.
"""
import json
import re
import sys

SIG_MIN, SIG_MAX = 9, 73          # a DER signature plus its hashtype byte
OP_CODESEPARATOR = 0xab


def opcodes(core):
    """OP_NAME -> byte, from Core's script.h enum."""
    src = open(f"{core}/src/script/script.h").read()
    return {m.group(1): int(m.group(3), 16)
            for m in re.finditer(r"\b(OP_([A-Z0-9_]+)) = (0x[0-9a-fA-F]+),", src)}


def push(data):
    """CScript::operator<<(vector), the minimal push encoding."""
    n = len(data)
    if n < 0x4c:
        return bytes([n]) + data
    if n <= 0xff:
        return b"\x4c" + bytes([n]) + data
    if n <= 0xffff:
        return b"\x4d" + n.to_bytes(2, "little") + data
    return b"\x4e" + n.to_bytes(4, "little") + data


def parse_script(s, ops):
    """ParseScript() from Core's script_tests.cpp, for the token classes
    tx_valid.json uses: hex literals, integers, quoted strings, opcode names."""
    out = b""
    for tok in s.split():
        if tok.startswith("0x"):
            out += bytes.fromhex(tok[2:])           # raw bytes, not a push
        elif re.fullmatch(r"-?\d+", tok):
            v = int(tok)
            if v == -1 or 1 <= v <= 16:
                out += bytes([ops["OP_1NEGATE"] if v == -1 else ops["OP_1"] + v - 1])
            elif v == 0:
                out += bytes([ops["OP_0"]])
            else:
                neg, v = v < 0, abs(v)
                b = bytearray()
                while v:
                    b.append(v & 0xff)
                    v >>= 8
                if b[-1] & 0x80:
                    b.append(0x80 if neg else 0)
                elif neg:
                    b[-1] |= 0x80
                out += push(bytes(b))
        elif tok.startswith("'") and tok.endswith("'"):
            out += push(tok[1:-1].encode())
        else:
            name = tok if tok.startswith("OP_") else "OP_" + tok
            if name not in ops:
                raise KeyError(tok)
            out += bytes([ops[name]])
    return out


def pushes(script):
    """The pushed items of a script, or None if it is not pushes alone."""
    items, o = [], 0
    while o < len(script):
        n = script[o]
        o += 1
        if n < 0x4c:
            pass
        elif n == 0x4c:
            if o >= len(script):
                return None
            n = script[o]
            o += 1
        else:
            return None
        if o + n > len(script):
            return None
        items.append(script[o:o + n])
        o += n
    return items


SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def strict_low_s(sig):
    """Whether a DER signature is strictly encoded and low-S, which is what a
    default node's mempool requires today and what kw_ec_verify enforces.

    tx_valid.json predates BIP62 and BIP66, so a good few of its signatures are
    high-S or loosely encoded. Those were valid when the vector was written and
    would be refused by any node now, so they say nothing about whether pc's
    digest is right and are dropped rather than shipped as expected failures.
    This reads bytes only; no signature is checked here."""
    if len(sig) < 8 or sig[0] != 0x30 or sig[1] != len(sig) - 2:
        return False
    if sig[2] != 0x02:
        return False
    rlen = sig[3]
    if rlen == 0 or 4 + rlen >= len(sig):
        return False
    r = sig[4:4 + rlen]
    o = 4 + rlen
    if sig[o] != 0x02:
        return False
    slen = sig[o + 1]
    if slen == 0 or o + 2 + slen != len(sig):
        return False
    s = sig[o + 2:o + 2 + slen]
    for v in (r, s):                                  # no negatives, no padding
        if v[0] & 0x80:
            return False
        if len(v) > 1 and v[0] == 0x00 and not (v[1] & 0x80):
            return False
    return int.from_bytes(s, "big") <= SECP256K1_N // 2


def scan_pushes(script):
    """Every pushed item in a script, stepping over the opcodes between them.
    pushes() is deliberately strict because a scriptSig that is not pushes alone
    is not one of these vectors; a script code holds real opcodes, so pulling
    the pubkeys out of one needs a walk that tolerates them."""
    out, o = [], 0
    while o < len(script):
        n = script[o]
        o += 1
        if n < 0x4c:
            pass
        elif n == 0x4c:
            if o >= len(script):
                break
            n = script[o]
            o += 1
        elif n in (0x4d, 0x4e):
            w = 2 if n == 0x4d else 4
            if o + w > len(script):
                break
            n = int.from_bytes(script[o:o + w], "little")
            o += w
        else:
            continue                                  # an opcode, not a push
        if o + n > len(script):
            break
        out.append(script[o:o + n])
        o += n
    return out


def scriptsig(raw):
    """The single input's scriptSig, or None if the tx is not single-input."""
    b = bytes.fromhex(raw)
    if len(b) < 42 or b[4] != 1:                     # varint 1, one byte
        return None
    o = 4 + 1 + 36
    n = b[o]
    o += 1
    if n >= 0xfd or o + n > len(b):
        return None
    return b[o:o + n]


def script_code(spk, items):
    """What the digest is taken over. For P2SH that is the redeem script the
    scriptSig pushes last, which is the same rule pc follows in verify_sigs;
    for everything else it is the scriptPubKey itself."""
    if len(spk) == 23 and spk[0] == 0xa9 and spk[1] == 0x14 and spk[22] == 0x87:
        return items[-1] if items else None
    return spk


def main():
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} /path/to/dogecoin")
    core = sys.argv[1]
    ops = opcodes(core)
    data = json.load(open(f"{core}/src/test/data/tx_valid.json"))

    rows, seen = [], set()
    for entry in data:
        if len(entry) != 3:
            continue                                  # a comment row
        prevs, raw, _flags = entry
        if len(prevs) != 1:
            continue
        ss = scriptsig(raw)
        if ss is None:
            continue
        items = pushes(ss)
        if items is None:                             # not pushes alone
            continue
        try:
            spk = parse_script(prevs[0][2], ops)
        except (KeyError, ValueError):
            continue

        code = script_code(spk, items)
        # pc splices the script code in whole, so a script Core would strip
        # separators out of is outside what it claims to compute.
        if not code or OP_CODESEPARATOR in code:
            continue

        # SIGHASH_ALL only: pc's digest hardcodes hashtype 1.
        sigs = [x for x in items
                if SIG_MIN <= len(x) <= SIG_MAX and x[-1] == 0x01
                and strict_low_s(x[:-1])]

        # Core deletes a signature from the script code before hashing it
        # (FindAndDelete, in the CHECKSIG path). pc splices the code in whole,
        # the same limit that rules out OP_CODESEPARATOR above, so a vector
        # built to exercise that rule is not one pc claims to answer.
        sigs = [x for x in sigs if x not in code]
        keys = [x for x in items + scan_pushes(code) if len(x) in (33, 65)]
        if not sigs or not keys:
            continue

        key = (code.hex(), raw)
        if key in seen:
            continue
        seen.add(key)
        # without the trailing hashtype byte, which belongs to the script and
        # not to the DER signature a verifier is handed
        rows.append((code.hex(),
                     ",".join(k.hex() for k in keys),
                     ",".join(s[:-1].hex() for s in sigs),
                     raw))

    print("# sighash vectors, derived from Dogecoin Core's src/test/data/tx_valid.json")
    print("# by test/mkvectors.py. Do not edit by hand; regenerate instead.")
    print("#")
    print("# Every row is a transaction Core's own test suite asserts is valid, so its")
    print("# signature verifies only against the digest consensus really uses. pc")
    print("# recomputes that digest with pc_tx_sighash() over script_code and checks")
    print("# the signature against it. A wrong digest cannot pass by coincidence.")
    print("#")
    print("# Signatures and pubkeys are given as candidate lists rather than paired:")
    print("# which key signed is not recorded in the data, and the assertion that")
    print("# matters is that some pair verifies, which no wrong digest satisfies.")
    print("#")
    print("# script_code pubkeys signatures raw_tx")
    for r in rows:
        print(" ".join(r))
    print(f"# {len(rows)} vectors", file=sys.stderr)


if __name__ == "__main__":
    main()
