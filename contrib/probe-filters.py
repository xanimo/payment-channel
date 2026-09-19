#!/usr/bin/env python3
"""Probe dogecoin mainnet peers for NODE_COMPACT_FILTERS (bit 6, 0x40).

kwd needs a peer serving bip158 filters and exits at startup without one, and
--daemon is the confirm path the README documents for mainnet, so whether such a
peer exists decides whether that path can be deployed at all. This takes the
number rather than trusting the claim: it resolves dogecoin's dns seeds, does a
version handshake with every address they return, and reports the service bits.

Run from anywhere; it needs no node, no keys and no koinu. It reads the network
and writes nothing.

    $ contrib/probe-filters.py

The answer on 2026-09-18 was 47 of 47 answering and one advertising filters,
which was the probing network's own node, so zero third-party peers. If that ever
changes, the prerequisite in the README changes with it.
"""
import socket, struct, hashlib, time, sys, random

MAGIC = 0xc0c0c0c0
PORT  = 22556
SEEDS = ["seed.multidoge.org", "seed2.multidoge.org",
         "seed.dogecoin.com", "seed.dogecoin.wiki"]

NODE_NETWORK         = 1 << 0
NODE_BLOOM           = 1 << 2
NODE_WITNESS         = 1 << 3
NODE_COMPACT_FILTERS = 1 << 6
NODE_NETWORK_LIMITED = 1 << 10

def msg(cmd, payload):
    h = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return struct.pack("<L12sL4s", MAGIC, cmd.encode(), len(payload), h) + payload

def netaddr(services, ip, port):
    return struct.pack("<Q", services) + b"\x00"*10 + b"\xff\xff" + \
           socket.inet_aton(ip) + struct.pack(">H", port)

def version_payload(ip):
    p  = struct.pack("<lQq", 70015, 0, int(time.time()))
    p += netaddr(0, ip, PORT) + netaddr(0, "0.0.0.0", 0)
    p += struct.pack("<Q", random.getrandbits(64))
    ua = b"/probe:0.1/"
    p += bytes([len(ua)]) + ua + struct.pack("<lB", 0, 0)
    return p

def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c: raise EOFError
        b += c
    return b

def probe(ip, timeout=6):
    s = socket.create_connection((ip, PORT), timeout)
    try:
        s.sendall(msg("version", version_payload(ip)))
        deadline = time.time() + timeout
        while time.time() < deadline:
            hdr = recv_exact(s, 24)
            magic, cmd, ln, _ = struct.unpack("<L12sL4s", hdr)
            body = recv_exact(s, ln) if ln else b""
            if cmd.rstrip(b"\x00") == b"version":
                ver, svc = struct.unpack("<lQ", body[:12])
                n = body[80]
                ua = body[81:81+n].decode("ascii", "replace")
                return svc, ver, ua
        return None
    finally:
        s.close()

addrs = set()
for sd in SEEDS:
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(sd, PORT, socket.AF_INET, socket.SOCK_STREAM):
            addrs.add(sa[0])
    except Exception as e:
        print(f"  seed {sd}: {e}", file=sys.stderr)

addrs = sorted(addrs)
print(f"{len(addrs)} addresses from {len(SEEDS)} seeds\n")

answered = cf = 0
for ip in addrs:
    try:
        r = probe(ip)
        if not r:
            print(f"  {ip:<18} no version"); continue
        svc, ver, ua = r
        answered += 1
        flags = []
        if svc & NODE_NETWORK:         flags.append("network")
        if svc & NODE_BLOOM:           flags.append("bloom")
        if svc & NODE_WITNESS:         flags.append("witness")
        if svc & NODE_COMPACT_FILTERS: flags.append("COMPACT_FILTERS"); cf += 1
        if svc & NODE_NETWORK_LIMITED: flags.append("limited")
        print(f"  {ip:<18} services 0x{svc:x} [{' '.join(flags)}] {ua}")
    except Exception as e:
        print(f"  {ip:<18} {type(e).__name__}")

print(f"\n{answered}/{len(addrs)} answered the handshake")
print(f"{cf}/{answered} advertise NODE_COMPACT_FILTERS (bit 6, 0x40)")
