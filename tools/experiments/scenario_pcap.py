"""Shared helper: build a classic PCAP whose 5-second windows have exactly specified feature values.
A window spec is a dict: n (packets), sizes (list of on-wire frame sizes, cycled), ports (list, cycled),
ips (list of last-octet ints, cycled). Frames are Ethernet/IPv4/TCP. The first packet of every window
is exactly at the window start (t0 + 5 i) and the rest are spread evenly inside it, so NetSentinel's grid
(anchored at the first packet) coincides with the scenario's windows."""
import struct, socket

HDR = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def frame(dst_last_octet, dport, size):
    size = max(54, int(size))
    payload = size - 54
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + payload, 0, 0, 64, 6, 0,
                     socket.inet_aton("192.168.1.50"), socket.inet_aton("10.0.%d.%d" % (dst_last_octet // 250, dst_last_octet % 250 + 1)))
    tcp = struct.pack("!HHIIHHHH", 50000, dport, 0, 0, (5 << 12) | 0x10, 8192, 0, 0)
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip + tcp + bytes(payload)

def build(windows, t0=1000.0):
    out = bytearray(HDR)
    for i, w in enumerate(windows):
        n = w["n"]; start = t0 + 5.0 * i
        for k in range(n):
            ts = start + k * 5.0 / n
            d = frame(w["ips"][k % len(w["ips"])], w["ports"][k % len(w["ports"])], w["sizes"][k % len(w["sizes"])])
            s = int(ts); us = int(round((ts - s) * 1e6))
            if us >= 1000000: s += 1; us -= 1000000
            out += struct.pack("<IIII", s, us, len(d), len(d)) + d
    return bytes(out)

def window(n=20, size=146, ports=(80, 443), ips=(5, 6, 7), small_packets=0, small_size=60):
    sizes = [small_size] * small_packets + [size] * (n - small_packets)
    return {"n": n, "sizes": sizes, "ports": list(ports), "ips": list(ips)}
