"""Audit regression fixtures (from the 29 Oct independent audit's craft.py, unchanged in content).
Each fixture isolates one defect of the original prototype (see docs/CHANGES.md). usage: make_audit_fixtures.py OUT_DIR [--force]
Never overwrites a DIFFERENT existing file unless --force (same policy as make_fixtures.py).
Addition: unsupported_linktype.pcap (DLT 101, raw IP) for the unsupported-link-type error path."""
import os, struct, socket, sys, hashlib

_a = [x for x in sys.argv[1:] if x != "--force"]; FORCE = "--force" in sys.argv[1:]
if len(_a) != 1: print(__doc__); sys.exit(2)
OUT = _a[0]
os.makedirs(OUT, exist_ok=True)
RC = 0

ETH_DST = b"\xaa\xbb\xcc\x00\x00\x01"
ETH_SRC = b"\xaa\xbb\xcc\x00\x00\x02"

def ipv4(proto, src, dst, payload, flags_frag=0, ihl=5):
    opts = bytes((ihl - 5) * 4)
    total = ihl * 4 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, 0, total, 0, flags_frag, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + opts + payload

def tcp(sport, dport, payload=b""):
    return struct.pack("!HHIIHHHH", sport, dport, 0, 0, (5 << 12) | 0x10, 8192, 0, 0) + payload

def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload

def eth(payload, ethertype=0x0800):
    return ETH_DST + ETH_SRC + struct.pack("!H", ethertype) + payload

def write(name, packets, linktype=1, snaplen=65535, truncate_last_bytes=0):
    """packets: list of (ts, frame_bytes, orig_len or None)"""
    path = os.path.join(OUT, name)
    buf = bytearray(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, snaplen, linktype))
    for ts, data, orig in packets:
        sec = int(ts); usec = int(round((ts - sec) * 1e6))
        buf += struct.pack("<IIII", sec, usec, len(data), orig if orig else len(data)) + data
    if truncate_last_bytes:
        buf = buf[:-truncate_last_bytes]
    global RC
    data = bytes(buf); h = hashlib.sha256(data).hexdigest()
    if os.path.exists(path):
        if open(path, "rb").read() == data: print("present, identical  %s  %s" % (h, name)); return
        if not FORCE: print("REFUSING to overwrite DIFFERENT existing file: %s" % path); RC = 3; return
    with open(path, "wb") as f:
        f.write(data)
    print("wrote               %s  %s" % (h, name))

def baseline_window(t0, n=20, size_payload=100, ports=(80, 443), ips=3):
    pk = []
    for k in range(n):
        dst = f"10.0.0.{5 + k % ips}"
        pk.append((t0 + k * 5.0 / n, eth(ipv4(6, "192.168.1.50", dst, tcp(50000 + k, ports[k % len(ports)], bytes(size_payload)))), None))
    return pk

def baseline(nwin, start=1000.0, jitter=True):
    pk = []
    for i in range(nwin):
        n = 18 + (i % 5) if jitter else 20
        pk += baseline_window(start + 5.0 * i, n=n, size_payload=92 + (i % 4) * 4,
                              ports=(80, 443) if i % 2 == 0 else (80, 443, 8080), ips=3 + i % 3)
    return pk

# 1. Idle gap: 25 normal windows, 10 minute silence, then 3 normal windows
pk = baseline(25)
pk += baseline(3, start=1000.0 + 25 * 5 + 600)
write("gap_10min.pcap", pk)

# 2. One packet carrying a future timestamp (+1 h clock glitch) in the middle
pk = baseline(30)
pk.insert(len(pk) // 2, (1000.0 + 75.0 + 3600.0, eth(ipv4(6, "192.168.1.50", "10.0.0.5", tcp(1, 80))), None))
pk.sort(key=lambda p: p[0])  # NOT sorted in a real capture; keep file order instead:
pk = baseline(30)
mid = len(pk) // 2
pk = pk[:mid] + [(1000.0 + 75.0 + 3600.0, eth(ipv4(6, "192.168.1.50", "10.0.0.5", tcp(1, 80))), None)] + pk[mid:]
write("future_ts_glitch.pcap", pk)

# 3. First packet with ts=0 (bad clock), then normal epoch traffic
pk = [(0.0, eth(ipv4(6, "192.168.1.50", "10.0.0.5", tcp(1, 80))), None)] + baseline(2, start=1_700_000_000.0)
write("epoch_zero_first.pcap", pk)

# 4. Truncated file: sample-like traffic, last record cut in half (read error mid-file)
pk = baseline(30)
write("truncated_file.pcap", pk, truncate_last_bytes=60)
write("truncated_file_full.pcap", pk)

# 5. Linux cooked capture (DLT_LINUX_SLL = 113): 16-byte SLL header, proto at bytes 14-15
def sll(payload):
    return struct.pack("!HHH8sH", 0, 1, 6, ETH_SRC + b"\x00\x00", 0x0800) + payload
pk = [(t, sll(f[14:]), None) for t, f, _ in baseline(30)]
write("linux_sll.pcap", pk, linktype=113)

# 6. 802.1Q VLAN-tagged traffic (otherwise identical baseline)
def vlan(frame):
    return frame[:12] + struct.pack("!HH", 0x8100, 10) + frame[12:]
pk = [(t, vlan(f), None) for t, f, _ in baseline(30)]
write("vlan_tagged.pcap", pk)

# 7. Snaplen 64: frames truncated on capture; orig_len 1514
pk = []
for i in range(30):
    for k in range(20):
        full = eth(ipv4(6, "192.168.1.50", "10.0.0.5", tcp(50000 + k, 443, bytes(1460))))
        pk.append((1000.0 + 5 * i + k * 0.25, full[:64], len(full)))
write("snaplen64.pcap", pk, snaplen=64)

# 8. Non-first IP fragments: UDP fragments whose payload bytes look like random "ports"
pk = baseline(25)
t0 = 1000.0 + 25 * 5
for k in range(40):
    payload = struct.pack("!HH", 1000 + 37 * k, 2000 + 53 * k) + bytes(100)  # data, not a header
    # flags_frag: offset = 185 (x8 = 1480 bytes) -> a non-first fragment
    pk.append((t0 + k * 0.1, eth(ipv4(17, "192.168.1.50", "10.0.0.5", payload, flags_frag=185)), None))
pk += baseline(3, start=t0 + 5)
write("fragments.pcap", pk)

# 9. TCP truncated by snaplen after IP header (12 transport bytes only)
pk = baseline(25)
t0 = 1000.0 + 25 * 5
for k in range(20):
    full = eth(ipv4(6, "192.168.1.50", "10.0.0.5", tcp(50000 + k, 443, bytes(200))))
    pk.append((t0 + k * 0.25, full[:14 + 20 + 12], len(full)))
write("tcp_truncated_hdr.pcap", pk)

# 10. Sample-like file WITHOUT the attack window: does the trailing partial window alert?
pk = baseline(29)
for k in range(4):
    pk.append((1000.0 + 145 + 0.2 * k, eth(ipv4(6, "192.168.1.50", "10.0.0.5", tcp(51000 + k, 80, bytes(100)))), None))
write("no_attack_with_tail.pcap", pk)

# 11. Constant baseline (2 ports every window) followed by a port scan of 1000 ports
pk = []
for i in range(30):
    for k in range(20):
        pk.append((1000.0 + 5 * i + 0.25 * k, eth(ipv4(6, "192.168.1.50", f"10.0.0.{5 + k % 3}", tcp(50000 + k, (80, 443)[k % 2], bytes(100)))), None))
t0 = 1000.0 + 150
for k in range(1000):
    pk.append((t0 + k * 0.004, eth(ipv4(6, "192.168.1.50", "10.0.0.5", tcp(40000, 1 + k))), None))
write("constant_then_scan.pcap", pk)

# 12. IPv6-only attack window inside IPv4 baseline (ethertype 0x86DD)
pk = baseline(25)
t0 = 1000.0 + 125
for k in range(500):
    v6 = struct.pack("!IHBB16s16s", 6 << 28, 20, 6, 64, bytes(16), bytes(15) + bytes([k % 256])) + tcp(40000, 1 + k)
    pk.append((t0 + k * 0.01, eth(v6, 0x86DD), None))
pk += baseline(3, start=t0 + 5)
write("ipv6_attack.pcap", pk)

# 11b. Same constant baseline and scan, followed by 3 constant windows, so the scan window is NOT
# the final (partial, unscored) window. Used for the constant-feature blind spot and the SD floor.
pk = []
for i in range(30):
    for k in range(20):
        pk.append((1000.0 + 5 * i + 0.25 * k, eth(ipv4(6, "192.168.1.50", f"10.0.0.{5 + k % 3}", tcp(50000 + k, (80, 443)[k % 2], bytes(100)))), None))
t0 = 1000.0 + 150
for k in range(1000):
    pk.append((t0 + k * 0.004, eth(ipv4(6, "192.168.1.50", "10.0.0.5", tcp(40000, 1 + k))), None))
for i in range(31, 34):
    for k in range(20):
        pk.append((1000.0 + 5 * i + 0.25 * k, eth(ipv4(6, "192.168.1.50", f"10.0.0.{5 + k % 3}", tcp(50000 + k, (80, 443)[k % 2], bytes(100)))), None))
write("constant_then_scan_tail.pcap", pk)

# 13. Unsupported link type (LINKTYPE_RAW = 101 in the file; libpcap reports DLT_RAW, 12 on Linux and macOS): must be rejected with an error, not parsed as nothing
pk = [(t, f[14:], None) for t, f, _ in baseline(3)]
write("unsupported_linktype.pcap", pk, linktype=101)

sys.exit(RC)
