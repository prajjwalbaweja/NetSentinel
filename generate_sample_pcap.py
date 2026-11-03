import struct
import socket

import sys, os
# Optional output path; refuses to overwrite an existing file unless --force.
# The default output is data/sample.pcap next to this script.
_args = [a for a in sys.argv[1:] if a != "--force"]
FORCE = "--force" in sys.argv[1:]
OUT = _args[0] if _args else os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "sample.pcap")

def ip_to_bytes(ip):
    return socket.inet_aton(ip)

def eth_frame(dst_mac, src_mac, ethertype, payload):
    return dst_mac + src_mac + struct.pack("!H", ethertype) + payload

def ipv4_header(total_length, proto, src_ip, dst_ip, ident=0):
    version_ihl = 0x45
    dscp_ecn = 0
    flags_frag = 0
    ttl = 64
    checksum = 0  # not validated by our parser
    return struct.pack("!BBHHHBBH4s4s",
                        version_ihl, dscp_ecn, total_length, ident, flags_frag,
                        ttl, proto, checksum, ip_to_bytes(src_ip), ip_to_bytes(dst_ip))

def tcp_header(src_port, dst_port, flags=0x02, payload_len=0):
    seq = 0
    ack = 0
    data_offset_flags = (5 << 12) | flags  # data offset 5 (no options), flags in low byte
    window = 8192
    checksum = 0
    urgent = 0
    return struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack,
                        data_offset_flags, window, checksum, urgent)

def build_tcp_packet(src_ip, dst_ip, src_port, dst_port, payload_len, flags=0x10):
    payload = bytes(payload_len)
    tcp_len = 20 + payload_len
    ip_total_len = 20 + tcp_len
    ip_hdr = ipv4_header(ip_total_len, 6, src_ip, dst_ip)
    tcp_hdr = tcp_header(src_port, dst_port, flags=flags)
    eth = eth_frame(b"\xaa\xbb\xcc\x00\x00\x01", b"\xaa\xbb\xcc\x00\x00\x02", 0x0800,
                     ip_hdr + tcp_hdr + payload)
    return eth

def build_arp_like_packet():
    # Non-IPv4 ethertype (ARP, 0x0806) -- FeatureExtractor must reject this
    # (extract() returns nullopt), not crash. Minimal ARP-ish payload.
    payload = bytes(28)
    return eth_frame(b"\xff\xff\xff\xff\xff\xff", b"\xaa\xbb\xcc\x00\x00\x02", 0x0806, payload)

def build_truncated_packet():
    # Shorter than a full 14-byte Ethernet header -- must be rejected as
    # an incomplete header, not read out of bounds.
    return b"\x00\x01\x02\x03\x05"

packets = []  # list of (timestamp_sec, raw_bytes)
BASE_T = 1000.0  # small base so window timestamps print as readable small numbers

MONITORED_HOST = "192.168.1.50"

# ---- Baseline windows: i = 0..24 (25 windows, 0s - 125s) ----
malformed_injected = 0
for i in range(25):
    w_start = i * 5.0
    packet_count = 20 + (i % 5) - 2            # 18,19,20,21,22 cycling
    payload_len = 92 + (i % 4) * 4              # 92,96,100,104 cycling -> total size 146..158
    ports = [80, 443] if i % 2 == 0 else [80, 443, 8080]
    ip_pool_size = 3 + (i % 3)                  # 3,4,5 cycling
    ip_pool = [f"10.0.0.{5+k}" for k in range(ip_pool_size)]

    for k in range(packet_count):
        t = w_start + (k * (5.0 / packet_count))
        dst_port = ports[k % len(ports)]
        dst_ip = ip_pool[k % len(ip_pool)]
        pkt = build_tcp_packet(MONITORED_HOST, dst_ip, 50000 + (k % 100), dst_port,
                                payload_len, flags=0x10)  # ACK -- established traffic
        packets.append((BASE_T + t, pkt))

    # Sprinkle a couple of deliberately malformed / non-IPv4 packets into the
    # baseline stream so the runtime evidence actually exercises the
    # malformed-packet path, not just the happy path.
    if i == 5:
        packets.append((BASE_T + w_start + 1.0, build_arp_like_packet()))
        malformed_injected += 1
    if i == 12:
        packets.append((BASE_T + w_start + 2.0, build_truncated_packet()))
        malformed_injected += 1
    if i == 18:
        packets.append((BASE_T + w_start + 3.0, build_arp_like_packet()))
        malformed_injected += 1

# ---- Attack window: i = 25 (125s - 130s) -- port scan / volumetric spike ----
ATTACK_START = 25 * 5.0
attack_packet_count = 150
attack_dst_ips = [f"10.0.1.{n}" for n in range(1, 21)]   # 20 distinct IPs
attack_ports = list(range(1, 51))                          # 50 distinct ports
for k in range(attack_packet_count):
    t = ATTACK_START + (k * (5.0 / attack_packet_count))
    dst_ip = attack_dst_ips[k % len(attack_dst_ips)]
    dst_port = attack_ports[k % len(attack_ports)]
    pkt = build_tcp_packet(MONITORED_HOST, dst_ip, 40000 + (k % 100), dst_port,
                            payload_len=0, flags=0x02)  # SYN, no payload -- scan-like
    packets.append((BASE_T + t, pkt))

# ---- Return to baseline: i = 26..28 (130s - 145s) ----
for i in range(26, 29):
    w_start = i * 5.0
    packet_count = 20 + (i % 5) - 2
    payload_len = 92 + (i % 4) * 4
    ports = [80, 443] if i % 2 == 0 else [80, 443, 8080]
    ip_pool_size = 3 + (i % 3)
    ip_pool = [f"10.0.0.{5+k}" for k in range(ip_pool_size)]
    for k in range(packet_count):
        t = w_start + (k * (5.0 / packet_count))
        dst_port = ports[k % len(ports)]
        dst_ip = ip_pool[k % len(ip_pool)]
        pkt = build_tcp_packet(MONITORED_HOST, dst_ip, 50000 + (k % 100), dst_port,
                                payload_len, flags=0x10)
        packets.append((BASE_T + t, pkt))

# ---- Trailing partial window: a handful of packets with < 5s of span,
# then EOF -- exercises the "final partial window closed at EOF" path. ----
TAIL_START = 29 * 5.0
for k in range(4):
    t = TAIL_START + k * 0.2
    pkt = build_tcp_packet(MONITORED_HOST, "10.0.0.5", 51000 + k, 80, 100, flags=0x10)
    packets.append((BASE_T + t, pkt))

packets.sort(key=lambda p: p[0])

# ---- Write the PCAP file ----
import os
if os.path.exists(OUT) and not FORCE:
    print(f"REFUSING to overwrite existing file: {OUT} (pass --force to override)")
    sys.exit(3)
os.makedirs(os.path.dirname(os.path.abspath(OUT)), exist_ok=True)
with open(OUT, "wb") as f:
    # Global header (classic pcap, little-endian, microsecond resolution)
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for t, data in packets:
        ts_sec = int(t)
        ts_usec = int(round((t - ts_sec) * 1_000_000))
        incl_len = len(data)
        orig_len = len(data)
        f.write(struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len))
        f.write(data)

print(f"Wrote {len(packets)} packets ({malformed_injected} deliberately malformed/non-IPv4) to {OUT}")
print(f"Time span: {packets[0][0] - BASE_T:.1f}s to {packets[-1][0] - BASE_T:.1f}s")
