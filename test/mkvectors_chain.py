#!/usr/bin/env python3
"""Derive sighash vectors for test/sighash_vectors.c from the Dogecoin chain.

test/mkvectors.py takes its vectors from Dogecoin Core's tx_valid.json, which
yields six: that file exists to exercise script flags, not to cover a digest.
These come from mainnet instead, where every confirmed P2PKH spend is a vector
whose signature the whole network already validated. The oracle is consensus
rather than a file, and there is no shortage of them.

Run against a synced datadir and commit the result:

    ./test/mkvectors_chain.py ~/.dogecoin/blocks > test/data/sighash_vectors_chain

Reads blk*.dat directly. No node runs, no RPC, and no txindex is needed: the
prevout scriptPubKey is not reconstructed from the spending input, it is read
off the output being spent, which this indexes while walking the same file. That
matters, because reconstructing it would mean this script deciding what the
digest covers, and then the vector would only prove this script agrees with pc.

AuxPoW blocks carry a merge-mining header between the block header and the
transactions. Rather than parse it, those blocks are skipped: each blk record is
length-prefixed, so skipping one is exact, and pre-AuxPoW blocks supply more
vectors than anyone needs.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mkvectors import strict_low_s, pushes          # noqa: E402

MAGIC = b"\xc0\xc0\xc0\xc0"
BLOCK_VERSION_AUXPOW = 0x100
WANT = int(os.environ.get("PC_VECTORS", "150"))


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class Reader:
    def __init__(self, b):
        self.b, self.o = b, 0

    def take(self, n):
        if self.o + n > len(self.b):
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
    raw = r.b[start:r.o]
    return raw, vin, vout


def p2pkh(spk):
    return (len(spk) == 25 and spk[0:3] == b"\x76\xa9\x14"
            and spk[23:25] == b"\x88\xac")


def blocks(path):
    """Every block in a blk file, skipping the AuxPoW ones."""
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
        if version & BLOCK_VERSION_AUXPOW:
            continue
        yield body


def main():
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} /path/to/.dogecoin/blocks")
    blockdir = sys.argv[1]

    utxo = {}                                         # txid -> [scriptPubKey]
    rows = []
    files = sorted(f for f in os.listdir(blockdir) if f.startswith("blk"))

    for name in files:
        for body in blocks(os.path.join(blockdir, name)):
            r = Reader(body)
            r.take(80)
            try:
                ntx = r.varint()
                txs = [read_tx(r) for _ in range(ntx)]
            except ValueError:
                continue                              # a truncated tail

            picked = False
            for raw, vin, vout in txs:
                utxo[dsha(raw)] = vout

                # one input, and not a coinbase
                if picked or len(vin) != 1:
                    continue
                prevout, index, script = vin[0]
                if prevout == b"\x00" * 32:
                    continue
                prev = utxo.get(prevout)
                if prev is None or index >= len(prev):
                    continue                          # spends an earlier file
                spk = prev[index]
                if not p2pkh(spk):
                    continue

                items = pushes(script)
                if items is None or len(items) != 2:
                    continue
                sig, pub = items
                if len(pub) not in (33, 65):
                    continue
                # SIGHASH_ALL only, and an encoding kw_ec_verify will accept:
                # mainnet predates BIP62, so plenty of these are high-S.
                if not sig or sig[-1] != 0x01 or not strict_low_s(sig[:-1]):
                    continue

                rows.append((spk.hex(), pub.hex(), sig[:-1].hex(), raw.hex()))
                picked = True                         # spread them over blocks

            if len(rows) >= WANT:
                break
        if len(rows) >= WANT:
            break

    print("# sighash vectors, derived from the dogecoin mainnet chain by")
    print("# test/mkvectors_chain.py. Do not edit by hand; regenerate instead.")
    print("#")
    print("# Every row is a confirmed P2PKH spend, so the network validated its")
    print("# signature against the digest consensus really uses. The scriptPubKey")
    print("# is the one on the output being spent, read off the chain rather than")
    print("# rebuilt from the input, so nothing here decides what the digest")
    print("# covers. pc recomputes it and checks the signature against it.")
    print("#")
    print("# script_code pubkeys signatures raw_tx")
    for r in rows:
        print(" ".join(r))
    print(f"# {len(rows)} vectors", file=sys.stderr)


if __name__ == "__main__":
    main()
