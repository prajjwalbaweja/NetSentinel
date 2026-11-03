"""Shared helpers for the NetSentinel evaluation tools (Python 3.8+, standard library only)."""
import csv, datetime, re, struct

# ---------------------------------------------------------------- NetSentinel trace (netsentinel-trace-v1)
def read_trace(path):
    """Returns (meta: dict, rows: list[dict]). Lines starting with '#' are metadata 'key=value'."""
    meta, body = {}, []
    with open(path, newline="") as fh:
        for line in fh:
            if line.startswith("#"):
                kv = line[1:].strip()
                if "=" in kv:
                    k, v = kv.split("=", 1); meta[k.strip()] = v.strip()
            else:
                body.append(line)
    rows = list(csv.DictReader(body))
    for r in rows:
        r["window_start"] = float(r["window_start"]); r["window_end"] = float(r["window_end"])
        r["alert"] = int(r["alert"]); r["window_index"] = int(r["window_index"])
    return meta, rows

def is_warmup(row):
    return any(row.get(k) == "warmup" for k in ("z_packet_count", "z_avg_packet_size", "z_unique_dst_ports", "z_unique_dst_ips"))

# ---------------------------------------------------------------- original-prototype console output -> trace-like rows
_PROTOTYPE_WIN = re.compile(r"^Window (\d+) \[([\d.]+)s - ([\d.]+)s\): packet_count=(\S+) avg_packet_size=(\S+) unique_dst_ports=(\S+) unique_dst_ips=(\S+)$")
def prototype_console_to_rows(text):
    """Converts the original prototype's (commit f0e39c0) console output into rows compatible with evaluate.py.
    The original prototype scores every window,
    including empty ones and the partial final window, so every window is 'scored' here."""
    rows, cur = [], None
    for line in text.splitlines():
        m = _PROTOTYPE_WIN.match(line)
        if m:
            cur = {"window_index": int(m.group(1)), "window_start": float(m.group(2)), "window_end": float(m.group(3)),
                   "status": "scored", "packet_count": m.group(4), "alert": 0, "triggered_features": "",
                   "z_packet_count": "", "z_avg_packet_size": "", "z_unique_dst_ports": "", "z_unique_dst_ips": ""}
            rows.append(cur); continue
        if cur is None: continue
        s = line.strip()
        for f in ("packet_count", "avg_packet_size", "unique_dst_ports", "unique_dst_ips"):
            if s.startswith(f + ": "):
                v = s[len(f) + 2:]
                cur["z_" + f] = "warmup" if v.startswith("warming up") else ("na" if v.startswith("z=N/A") else v[2:])
            if s.startswith("- " + f + ":"):
                cur["triggered_features"] = (cur["triggered_features"] + "+" if cur["triggered_features"] else "") + f
        if s.startswith("!! ANOMALY"): cur["alert"] = 1
    return rows

# ---------------------------------------------------------------- classic pcap reader (headers only)
def pcap_packets(path, max_packets=None):
    """Yields (ts, proto, src, dst, sport, dport) for IPv4 TCP/UDP packets (Ethernet, 802.1Q, Linux SLL).
    Raises ValueError for pcapng (convert with: editcap -F pcap in.pcapng out.pcap)."""
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24: raise ValueError("pcap global header truncated")
        magic = gh[:4]
        if magic == b"\x0a\x0d\x0d\x0a": raise ValueError("pcapng file: convert with 'editcap -F pcap in.pcapng out.pcap'")
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"): e = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"): e = ">"
        else: raise ValueError("not a classic pcap file")
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"); div = 1e9 if nano else 1e6
        linktype = struct.unpack(e + "I", gh[20:24])[0]
        rec = struct.Struct(e + "IIII"); n = 0
        while True:
            h = fh.read(16)
            if len(h) < 16: return
            s, us, incl, orig = rec.unpack(h); d = fh.read(incl)
            if len(d) < incl: return
            n += 1
            if max_packets and n > max_packets: return
            if linktype == 113:
                if len(d) < 16: continue
                et = (d[14] << 8) | d[15]; o = 16
            else:
                if len(d) < 14: continue
                et = (d[12] << 8) | d[13]; o = 14; tags = 0
                while et in (0x8100, 0x88A8) and tags < 2 and len(d) >= o + 4:
                    et = (d[o + 2] << 8) | d[o + 3]; o += 4; tags += 1
            if et != 0x0800 or len(d) < o + 20: continue
            ihl = (d[o] & 0x0F) * 4; proto = d[o + 9]
            if proto not in (6, 17) or len(d) < o + ihl + 4: continue
            if ((d[o + 6] << 8) | d[o + 7]) & 0x1FFF: continue
            src = "%d.%d.%d.%d" % tuple(d[o + 12:o + 16]); dst = "%d.%d.%d.%d" % tuple(d[o + 16:o + 20])
            t = o + ihl
            yield (s + us / div, proto, src, dst, (d[t] << 8) | d[t + 1], (d[t + 2] << 8) | d[t + 3])

# ---------------------------------------------------------------- CICFlowMeter / CICIDS2017 label CSV
def _norm(s): return re.sub(r"[^a-z0-9]", "", s.lower())

COLUMN_PATTERNS = {
    "timestamp": [r"^timestamp$"],
    "duration":  [r"^flowduration$"],
    "label":     [r"^label$"],
    "src":       [r"^(src|source)ip$"],
    "dst":       [r"^(dst|destination)ip$"],
    "sport":     [r"^(src|source)port$"],
    "dport":     [r"^(dst|destination)port$"],
    "proto":     [r"^protocol$"],
    "fwd_pkts":  [r"^tot(al)?fwdp(ac)?k(e)?t(s)?$", r"^totalfwdpackets?$", r"^totfwdpkts$"],
    "bwd_pkts":  [r"^tot(al)?(bwd|backward)p(ac)?k(e)?t(s)?$", r"^totalbackwardpackets$", r"^totbwdpkts$"],
}

def detect_columns(header):
    found = {}
    for key, pats in COLUMN_PATTERNS.items():
        for i, h in enumerate(header):
            if any(re.match(p, _norm(h)) for p in pats):
                found[key] = i; break
    missing = [k for k in ("timestamp", "duration", "label") if k not in found]
    if missing:
        raise ValueError("label CSV is missing required column(s) %s; header was: %s" % (missing, header[:20]))
    return found

TS_FORMATS = ["%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S",
              "%d/%m/%Y %H:%M", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M",
              "%d/%m/%Y %I:%M %p", "%Y/%m/%d %H:%M:%S", "%d-%m-%Y %H:%M:%S"]

class TimestampParser:
    """Parses label timestamps as naive wall-clock times and returns 'naive epoch' seconds (as if UTC).
    The true PCAP epoch = naive epoch + offset, where the offset is measured by align.py, never assumed.
    hour12_heuristic: original CICIDS2017 CSVs print afternoon times without AM/PM (e.g. 3:30 for 15:30);
    if set, hours 1..7 are moved to 13..19 (working hours were roughly 08:00-18:00). Off by default."""
    def __init__(self, fmt=None, hour12_heuristic=False):
        self.fmt = fmt; self.h12 = hour12_heuristic
    def __call__(self, s):
        s = s.strip()
        fmts = [self.fmt] if self.fmt else TS_FORMATS
        for f in fmts:
            try:
                dt = datetime.datetime.strptime(s, f)
            except ValueError:
                continue
            if not self.fmt: self.fmt = f      # lock the first format that works
            if self.h12 and "%p" not in f and 1 <= dt.hour <= 7: dt += datetime.timedelta(hours=12)
            return (dt - datetime.datetime(1970, 1, 1)).total_seconds()
        raise ValueError("unrecognised timestamp %r (pass --ts-format)" % s)

def read_flows(paths, ts_parser, label_filter=None):
    """Yields dicts: start (naive epoch), dur (s), label, attempted (bool), benign (bool), pkts, src, dst, sport, dport, proto."""
    for path in paths:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            rd = csv.reader(fh); header = next(rd); col = detect_columns(header)
            for row in rd:
                if not row or len(row) <= max(col.values()): continue
                if row[col["label"]].strip().lower() == "label": continue   # repeated header lines
                try:
                    start = ts_parser(row[col["timestamp"]]); dur = max(0.0, float(row[col["duration"]]) / 1e6)
                except ValueError:
                    continue
                label = row[col["label"]].strip()
                low = label.lower()
                pk = 0
                for k in ("fwd_pkts", "bwd_pkts"):
                    if k in col:
                        try: pk += int(float(row[col[k]]))
                        except ValueError: pass
                yield {"start": start, "dur": dur, "label": label, "attempted": "attempted" in low,
                       "benign": low == "benign", "pkts": pk,
                       "src": row[col["src"]].strip() if "src" in col else None,
                       "dst": row[col["dst"]].strip() if "dst" in col else None,
                       "sport": _int(row[col["sport"]]) if "sport" in col else None,
                       "dport": _int(row[col["dport"]]) if "dport" in col else None,
                       "proto": _int(row[col["proto"]]) if "proto" in col else None}

def _int(s):
    try: return int(float(s))
    except ValueError: return None

def attack_type(label):
    """'DoS Hulk - Attempted' -> 'DoS Hulk'; benign -> 'BENIGN'."""
    t = re.sub(r"\s*-\s*attempted\s*$", "", label.strip(), flags=re.I)
    return "BENIGN" if t.lower() == "benign" else t
