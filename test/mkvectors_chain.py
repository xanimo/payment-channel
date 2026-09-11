#!/usr/bin/env python3
"""Derive sighash vectors for test/sighash_vectors.c from the Dogecoin chain.

test/mkvectors.py takes its vectors from Dogecoin Core's tx_valid.json, which
yields six: that file exists to exercise script flags, not to cover a digest.
These come from mainnet instead, where every confirmed spend is a vector whose
signature the whole network already validated. The oracle is consensus rather
than a file, and there is no shortage of them.

Two shapes, because pc computes the digest over two:

  P2PKH   the script code is the scriptPubKey being spent. The common case.
  P2SH    the script code is the redeem script the scriptSig pushes last,
          which is the rule pc follows in verify_sigs and the shape pc's own
          channel actually uses. These are the vectors that cover pc.

Run against a synced datadir and commit the result:

    ./test/mkvectors_chain.py ~/.dogecoin/blocks > test/data/sighash_vectors_chain

Reads blk*.dat directly. No node runs, no RPC, and no txindex is needed: the
prevout scriptPubKey is not reconstructed from the spending input, it is read
off the output being spent, which this indexes while walking the same file. That
matters, because reconstructing it would mean this script deciding what the
digest covers, and then the vector would only prove this script agrees with pc.

Files are walked newest first. P2SH is absent from early Dogecoin (14,545
pre-AuxPoW blocks hold not one), so starting at the oldest would scan the whole
chain to find the shape that matters most. Within a file the walk is forward,
since a prevout is always in an earlier block than the spend that names it.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mkvectors import strict_low_s, pushes, scan_pushes, OP_CODESEPARATOR  # noqa: E402

MAGIC = b"\xc0\xc0\xc0\xc0"
BLOCK_VERSION_AUXPOW = 0x100
WANT_P2PKH = int(os.environ.get("PC_VECTORS_P2PKH", "100"))
WANT_P2SH = int(os.environ.get("PC_VECTORS_P2SH", "50"))
SIG_MIN, SIG_MAX = 9, 73


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class Reader:
    def __init__(self, b):
        self.b, self.o = b, 0

    def take(self, n):
        if n < 0 or self.o + n > len(self.b):
            raise ValueError("short")
        v = self.b[self.o:self.o + n]
        self.o += n
        return v

    def u(self, n):
        return int.from_bytes(self.take(n), "little")

    def varint(self):
        n = self.u(1)
        if n < 0xfd:
            return n
        return self.u(2 if n == 0xfd else 4 if n == 0xfe else 8)


def read_tx(r):
    """One transaction, returning its raw bytes and its parsed shape. Dogecoin
    has no segwit, so there is no marker to disambiguate and this is the only
    encoding a transaction has."""
    start = r.o
    r.u(4)                                            # version
    vin = []
    for _ in range(r.varint()):
        prevout = r.take(32)
        index = r.u(4)
        script = r.take(r.varint())
        r.u(4)                                        # sequence
        vin.append((prevout, index, script))
    vout = []
    for _ in range(r.varint()):
        r.u(8)                                        # value
        vout.append(r.take(r.varint()))               # scriptPubKey
    r.u(4)                                            # locktime
    return r.b[start:r.o], vin, vout


def skip_auxpow(r):
    """Merge-mining proof, between the header and the transactions. A CMerkleTx
    (the parent chain's coinbase, the block it was in, its merkle branch and
    index), then the chain merkle branch and index, then the parent header.
    Only its length matters here, so it is walked rather than checked."""
    read_tx(r)                                        # parent coinbase
    r.take(32)                                        # hashBlock
    r.take(r.varint() * 32); r.u(4)                   # vMerkleBranch, nIndex
    r.take(r.varint() * 32); r.u(4)                   # vChainMerkleBranch, nChainIndex
    r.take(80)                                        # parent block header


def blocks(path):
    """Every block in a blk file, AuxPoW walked rather than skipped."""
    with open(path, "rb") as f:
        data = f.read()
    o = 0
    while o + 8 <= len(data):
        if data[o:o + 4] != MAGIC:                    # trailing zero padding
            break
        size = int.from_bytes(data[o + 4:o + 8], "little")
        body = data[o + 8:o + 8 + size]
        o += 8 + size
        if len(body) < 81:
            continue
        version = int.from_bytes(body[0:4], "little")
        r = Reader(body)
        try:
            r.take(80)
            if version & BLOCK_VERSION_AUXPOW:
                skip_auxpow(r)
            yield [read_tx(r) for _ in range(r.varint())]
        except ValueError:
            continue                                  # a truncated tail


def p2pkh(spk):
    return (len(spk) == 25 and spk[0:3] == b"\x76\xa9\x14"
            and spk[23:25] == b"\x88\xac")


def p2sh(spk):
    return len(spk) == 23 and spk[0] == 0xa9 and spk[1] == 0x14 and spk[22] == 0x87


def vector(spk, script):
    """(kind, script_code, keys, sigs) for a spend pc's digest can answer, or
    None. The script code is the scriptPubKey for P2PKH and the redeem script
    for P2SH, which is the rule pc follows."""
    items = pushes(script)
    if items is None:                                 # not pushes alone
        return None

    if p2pkh(spk):
        kind, code, sigs = "p2pkh", spk, items[:1]
    elif p2sh(spk) and items:
        kind, code, sigs = "p2sh", items[-1], items[:-1]
    else:
        return None

    # pc splices the script code in whole, so a script Core would strip
    # separators out of is outside what it claims to compute.
    if not code or OP_CODESEPARATOR in code:
        return None

    sigs = [s for s in sigs
            if SIG_MIN <= len(s) <= SIG_MAX and s and s[-1] == 0x01
            and strict_low_s(s[:-1]) and s not in code]
    keys = [k for k in items + scan_pushes(code) if len(k) in (33, 65)]
    if not sigs or not keys:
        return None
    return kind, code, keys, sigs


def main():
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} /path/to/.dogecoin/blocks")
    blockdir = sys.argv[1]

    rows, have = [], {"p2pkh": 0, "p2sh": 0}
    want = {"p2pkh": WANT_P2PKH, "p2sh": WANT_P2SH}
    files = sorted((f for f in os.listdir(blockdir) if f.startswith("blk")),
                   reverse=True)

    for name in files:
        # Reset per file: a prevout in some other file is not in reach anyway,
        # and the whole chain's outputs do not belong in memory at once.
        utxo = {}
        for txs in blocks(os.path.join(blockdir, name)):
            picked = False
            for raw, vin, vout in txs:
                utxo[dsha(raw)] = vout
                if picked or len(vin) != 1:
                    continue
                prevout, index, script = vin[0]
                if prevout == b"\x00" * 32:           # coinbase
                    continue
                prev = utxo.get(prevout)
                if prev is None or index >= len(prev):
                    continue

                v = vector(prev[index], script)
                if not v:
                    continue
                kind, code, keys, sigs = v
                if have[kind] >= want[kind]:
                    continue
                have[kind] += 1
                rows.append((code.hex(),
                             ",".join(k.hex() for k in keys),
                             ",".join(s[:-1].hex() for s in sigs),
                             raw.hex()))
                picked = True                         # spread over blocks
            if all(have[k] >= want[k] for k in want):
                break
        if all(have[k] >= want[k] for k in want):
            break

    print("# sighash vectors, derived from the dogecoin mainnet chain by")
    print("# test/mkvectors_chain.py. Do not edit by hand; regenerate instead.")
    print("#")
    print("# Every row is a confirmed spend, so the network validated its")
    print("# signature against the digest consensus really uses. The script code")
    print("# is read off the chain rather than rebuilt from the input, so nothing")
    print("# here decides what the digest covers.")
    print("#")
    print(f"# {have['p2pkh']} P2PKH, where the script code is the scriptPubKey, and")
    print(f"# {have['p2sh']} P2SH, where it is the redeem script the scriptSig pushes")
    print("# last. The second shape is the one pc's own channel uses.")
    print("#")
    print("# script_code pubkeys signatures raw_tx")
    for r in rows:
        print(" ".join(r))
    print(f"# {have['p2pkh']} p2pkh + {have['p2sh']} p2sh = {len(rows)}", file=sys.stderr)


if __name__ == "__main__":
    main()
