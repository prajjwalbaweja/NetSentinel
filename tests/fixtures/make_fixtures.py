#!/usr/bin/env python3
"""Deterministic synthetic fixtures for NetSentinel characterization tests.

usage: make_fixtures.py OUT_DIR [--force]
Never overwrites: an existing identical file is left alone; an existing DIFFERENT file aborts (exit 3) unless --force.
Fixtures (classic pcap, little-endian, microsecond, linktype 1 Ethernet):
  empty.pcap        valid header, zero packets
  corrupt.pcap      not a pcap file
  trunc_global.pcap global header cut short (open() fails)
  trunc_data.pcap   one record header claiming 100 bytes, only 10 present
  trunc_hdr.pcap    one valid packet, then 5 stray bytes (partial record header)
  trunc_mid.pcap    25 normal windows (the baseline), file cut 37 bytes before its end, i.e. in the middle of the last record
  gap.pcap          25 baseline windows, 600 s silence, 1 normal window
  boundary.pcap     25 baseline windows, then window A (avg_packet_size z~2.97, no alert at 3.0), window B (z~3.05, alert), normal window
Boundary parameters were chosen by search against tests/oracle/oracle.py (see make_fixtures comments).
"""
import struct, socket, sys, os, hashlib
HDR = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
def pkt(dip, dport, pl=92):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + pl, 0, 0, 64, 6, 0, socket.inet_aton("192.168.1.50"), socket.inet_aton(dip))
    tcp = struct.pack("!HHIIHHHH", 50000, dport, 0, 0, (5 << 12) | 0x10, 8192, 0, 0)
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip + tcp + bytes(pl)
def rec(t, d):
    s = int(t); us = int(round((t - s) * 1e6)); return struct.pack("<IIII", s, us, len(d), len(d)) + d
def pcap(records): return HDR + b"".join(rec(t, d) for t, d in records)
def win(P, i, t0, n):  # the same baseline shape as data/sample.pcap baseline windows (ports {80,443}, 3..5 dst IPs)
    for k in range(n):
        P.append((t0 + k * 5.0 / n, pkt("10.0.0.%d" % (5 + k % (3 + i % 3)), 80 if k % 2 else 443, 92 + (i % 4) * 4)))
def win_mix(P, t0, n, base_pl, n_plus, ips=4):  # n packets; n_plus of them carry payload base_pl+1 -> avg size = 54+base_pl+n_plus/n
    for k in range(n):
        P.append((t0 + k * 5.0 / n, pkt("10.0.0.%d" % (5 + k % ips), 80 if k % 2 else 443, base_pl + (1 if k < n_plus else 0))))
def baseline(P):
    for i in range(25): win(P, i, 1000 + i * 5.0, 20 + (i % 5) - 2)
def build():
    F = {}
    F["empty.pcap"] = HDR
    F["corrupt.pcap"] = b"not a pcap file at all"
    F["trunc_global.pcap"] = HDR[:10]
    F["trunc_data.pcap"] = HDR + struct.pack("<IIII", 1000, 0, 100, 100) + b"0123456789"
    P = []; win(P, 0, 1000.0, 20); F["trunc_hdr.pcap"] = pcap(P) + b"\x01\x02\x03\x04\x05"
    P = []; baseline(P); win(P, 25, 1000 + 125 + 600, 20); F["gap.pcap"] = pcap(P)
    P = []; baseline(P); F["trunc_mid.pcap"] = pcap(P)[:-37]
    P = []; baseline(P)
    win_mix(P, 1125.0, 20, 111, 10)   # A: avg 165.50 -> z(avg_packet_size) ~ 2.967 vs 25-window baseline (no alert at threshold 3.0)
    win_mix(P, 1130.0, 20, 114, 7)    # B: avg 168.35 -> z ~ 3.054 vs baseline incl. A (alert at 3.0; none at 3.1)
    win(P, 27, 1135.0, 20)            # C: ordinary window
    F["boundary.pcap"] = pcap(P)
    return F
if __name__ == "__main__":
    a = [x for x in sys.argv[1:] if x != "--force"]; force = "--force" in sys.argv[1:]
    if len(a) != 1: print(__doc__); sys.exit(2)
    out = a[0]; os.makedirs(out, exist_ok=True); rc = 0
    for name, data in build().items():
        p = os.path.join(out, name); h = hashlib.sha256(data).hexdigest()
        if os.path.exists(p):
            if open(p, "rb").read() == data: print("present, identical  %s  %s" % (h, name)); continue
            if not force: print("REFUSING to overwrite DIFFERENT existing file: %s" % p); rc = 3; continue
        open(p, "wb").write(data); print("wrote               %s  %s" % (h, name))
    sys.exit(rc)
