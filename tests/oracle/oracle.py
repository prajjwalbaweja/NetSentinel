"""Independent Python reference for the NetSentinel pipeline CONTRACT (not a port of the C++ source).

Time, window and parsing contract, read from the written policy, not from Pipeline.cpp:
  parse   Ethernet (up to two 802.1Q/802.1ad tags) or Linux SLL; IPv4 v4, IHL>=5, header within caplen;
          ports only for TCP/UDP, fragment offset 0, >= 4 transport bytes; size = pcap orig_len.
  time    every packet advances the clock; late (< open window start) dropped; a packet more than
          GAP_CAP after the latest accepted timestamp is held one packet: if the next packet is back
          within GAP_CAP of that latest timestamp, the held one is quarantined, otherwise both are
          accepted; a held packet at EOF is quarantined.
  windows 5 s grid anchored at the first accepted packet; idle gaps emit at most GAP_CAP/5 empty
          windows, the rest is skipped; window open at EOF = partial.
  scoring only windows with >= 1 parsed packet are scored and learned (idle / no-parsed / partial are
          neither); per-feature Welford, 20-window warm-up, variance epsilon 1e-6 -> N/A,
          score-then-update, |z| > THRESH.  Cumulative baseline (b0) = always update (the only policy modelled here).
Written by the same author as the C++ changes: agreement shows the C++ matches this reading of the
contract, not that the contract is right.
"""
import struct, math
WINDOW = 5.0; WARMUP = 20; EPS = 1e-6; THRESH = 3.0; GAP_CAP = 60.0
NAMES = ["packet_count", "avg_packet_size", "unique_dst_ports", "unique_dst_ips"]

def read(path):
    """Returns (linktype, [(ts, bytes, orig_len)]). Stops at a truncated record."""
    d = open(path, "rb").read()
    if len(d) < 24: raise ValueError("global header truncated")
    magic = struct.unpack("<I", d[:4])[0]
    if magic not in (0xa1b2c3d4, 0xa1b23c4d): raise ValueError("unsupported pcap magic 0x%08x" % magic)
    div = 1e9 if magic == 0xa1b23c4d else 1e6
    linktype = struct.unpack("<I", d[20:24])[0]
    off = 24; pk = []
    while off + 16 <= len(d):
        s, us, il, ol = struct.unpack("<IIII", d[off:off + 16]); off += 16
        if off + il > len(d): break
        pk.append((s + us / div, d[off:off + il], ol)); off += il
    return linktype, pk

def parse(b, orig, linktype=1):
    """Returns (dst_ip, dst_port|None, wire_len) or None."""
    if linktype == 113:
        if len(b) < 16: return None
        et = struct.unpack("!H", b[14:16])[0]; ipo = 16
    else:
        if len(b) < 14: return None
        to = 12; et = struct.unpack("!H", b[12:14])[0]; tags = 0
        while et in (0x8100, 0x88A8) and tags < 2:
            to += 4
            if len(b) < to + 2: return None
            et = struct.unpack("!H", b[to:to + 2])[0]; tags += 1
        ipo = to + 2
    if et != 0x0800 or len(b) < ipo + 20: return None
    ip = b[ipo:]; ver, ihl = ip[0] >> 4, ip[0] & 0xF
    if ver != 4 or ihl < 5 or len(ip) < ihl * 4: return None
    proto = ip[9]; dip = ".".join(map(str, ip[16:20])); t = ihl * 4
    frag = struct.unpack("!H", ip[6:8])[0] & 0x1FFF
    port = None
    if proto in (6, 17) and frag == 0 and len(ip) >= t + 4:
        port = struct.unpack("!H", ip[t + 2:t + 4])[0]
    return dip, port, (orig if orig else len(b))

def windows(pk, linktype=1):
    """Returns list of (status, [features]) following the time/window contract."""
    out = []; st = {"t0": None, "start": None, "frontier": None, "held": None}
    cur = None
    def new(): return {"raw": 0, "n": 0, "sz": 0, "p": set(), "i": set()}
    def close(partial=False):
        X = st["cur"]
        if partial: status = "partial"
        elif X["raw"] == 0: status = "idle"
        elif X["n"] == 0: status = "no_parsed_traffic"
        else: status = "scored"
        out.append((status, [X["n"], (X["sz"] / X["n"]) if X["n"] else 0.0, len(X["p"]), len(X["i"])]))
        st["start"] += WINDOW; st["cur"] = new()
    def accept(t, b, o):
        if st["start"] is None: st["start"] = t; st["cur"] = new()
        if t < st["start"]: return                        # late: dropped
        if t >= st["start"] + WINDOW:
            close()
            k = int(math.floor((t - st["start"]) / WINDOW))
            capw = int(math.floor(GAP_CAP / WINDOW))
            if k > capw:
                for _ in range(capw): close()
                st["start"] += int(math.floor((t - st["start"]) / WINDOW)) * WINDOW
            else:
                for _ in range(k): close()
        if st["frontier"] is None or t > st["frontier"]: st["frontier"] = t
        X = st["cur"]; X["raw"] += 1
        r = parse(b, o, linktype)
        if r is None: return
        dip, port, n = r
        X["n"] += 1; X["sz"] += n; X["i"].add(dip)
        if port is not None: X["p"].add(port)
    for t, b, o in pk:
        if st["held"] is not None:
            h = st["held"]; st["held"] = None
            if t <= st["frontier"] + GAP_CAP: accept(t, b, o)   # held one quarantined
            else: accept(*h); accept(t, b, o)
            continue
        if st["frontier"] is not None and t > st["frontier"] + GAP_CAP:
            st["held"] = (t, b, o); continue
        accept(t, b, o)
    if st["start"] is not None: close(partial=True)
    return out

class Welford:
    def __init__(s): s.n = 0; s.m = 0.0; s.m2 = 0.0
    def var(s): return s.m2 / (s.n - 1) if s.n > 1 else 0.0
    def z(s, x):
        if s.n < WARMUP: return None
        v = s.var()
        return None if v < EPS else (x - s.m) / math.sqrt(v)
    def update(s, x): s.n += 1; d = x - s.m; s.m += d / s.n; s.m2 += d * (x - s.m)

def score(V):
    """V = windows(...). Returns (Z, alerts): Z[w] is None for unscored windows."""
    E = [Welford() for _ in range(4)]; Z = []; alerts = {}
    for w, (status, v) in enumerate(V):
        if status != "scored": Z.append(None); continue
        zs = [e.z(x) for e, x in zip(E, v)]; Z.append(zs)
        trig = {NAMES[k]: zs[k] for k in range(4) if zs[k] is not None and abs(zs[k]) > THRESH}
        if trig: alerts[w] = trig
        for e, x in zip(E, v): e.update(x)
    return Z, alerts
