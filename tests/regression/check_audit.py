#!/usr/bin/env python3
"""Closure checks for the defects found in the original prototype (docs/CHANGES.md). usage: check_audit.py --exe EXE --root ROOT --name FIXTURE
Runs EXE on tests/data/audit/FIXTURE.pcap (default options) and asserts the corrected outcome for that defect.
Each check states the defect it closes; failure prints the observed values."""
import sys, os, re, subprocess, argparse, time
ap = argparse.ArgumentParser(); ap.add_argument("--exe", required=True); ap.add_argument("--root", required=True)
ap.add_argument("--name", required=True); a = ap.parse_args()
root = os.path.abspath(a.root)
fixture, _, variant = a.name.partition("@")
extra = {"": [], "gated_sd_floor": ["--policy", "gated", "--sd-floor"]}[variant]
pcap = os.path.join("tests/data/audit", fixture + ".pcap")
t0 = time.time(); p = subprocess.run([a.exe, *extra, pcap], cwd=root, capture_output=True, text=True, timeout=60); dt = time.time() - t0
out = p.stdout
def counter(label):
    m = re.search(r"^\s*" + re.escape(label) + r":\s+(-?\d+)\s*$", out, re.M)
    return int(m.group(1)) if m else None
C = {k: counter(v) for k, v in {
    "read": "Packets read from PCAP", "parsed": "Packets parsed (IPv4)", "ipv6": "of which IPv6",
    "late": "Late packets dropped", "quar": "Far-future packets quarantined", "caps": "Idle gaps capped (60 s rule)",
    "emitted": "Windows emitted", "scored": "scored", "idle": "idle (not scored/learned)",
    "noparsed": "no parsed traffic (not scored/learned)", "partial": "partial final (not scored/learned)",
    "alerts": "Alerts raised"}.items()}
W = [dict(zip(("i", "pc", "avg", "ports", "ips"), (int(m[0]), int(m[1]), float(m[2]), int(m[3]), int(m[4]))))
     for m in re.findall(r"^Window (\d+) \[[\d.]+s - [\d.]+s\): packet_count=(\d+) avg_packet_size=(\S+) unique_dst_ports=(\d+) unique_dst_ips=(\d+)$", out, re.M)]
CHECKS = {
  "future_ts_glitch": ("far-future timestamp quarantined", lambda: p.returncode == 0 and C["quar"] == 1 and C["late"] == 0 and max(w["pc"] for w in W) < 40 and C["alerts"] == 0),
  "epoch_zero_first": ("epoch-0 first packet: gap capped", lambda: p.returncode == 0 and dt < 5 and C["caps"] == 1 and C["emitted"] < 50),
  "truncated_file":   ("read error exits 2", lambda: p.returncode == 2 and "PCAP read error" in p.stderr),
  "truncated_file_full": ("read error control: clean file exits 0", lambda: p.returncode == 0 and p.stderr == ""),
  "no_attack_with_tail": ("partial final window not scored", lambda: p.returncode == 0 and C["alerts"] == 0 and C["partial"] == 1),
  "gap_10min":        ("idle windows and IPv6 not learned", lambda: p.returncode == 0 and C["caps"] == 1 and C["idle"] == 12 and C["alerts"] == 0),
  "ipv6_attack":      ("idle windows and IPv6 not learned", lambda: p.returncode == 0 and C["ipv6"] == 500 and C["noparsed"] == 1 and C["alerts"] == 0
                                      and all(w["pc"] > 0 for w in W)),
  "vlan_tagged":      ("VLAN, Linux SLL and unsupported link types", lambda: p.returncode == 0 and C["parsed"] == 600),
  "linux_sll":        ("VLAN, Linux SLL and unsupported link types", lambda: p.returncode == 0 and C["parsed"] == 600),
  "unsupported_linktype": ("VLAN, Linux SLL and unsupported link types", lambda: p.returncode == 1 and "Unsupported PCAP link type" in p.stderr),
  "snaplen64":        ("average size from on-wire length", lambda: p.returncode == 0 and len(W) > 0 and all(w["avg"] == 1514 for w in W)),
  "fragments":        ("no ports from non-first fragments", lambda: p.returncode == 0 and max(w["ports"] for w in W) <= 3),
  "tcp_truncated_hdr": ("truncated TCP header: no port 0", lambda: p.returncode == 0 and C["parsed"] == 520),
  # constant_then_scan: the scan is in the final window, which is partial -> never scored.
  "constant_then_scan": ("scan in partial final window is not scored", lambda: p.returncode == 0 and C["alerts"] == 0 and C["partial"] == 1),
  # The cumulative baseline keeps the original constant-feature blind spot by design: z=N/A.
  "constant_then_scan_tail": ("constant-feature blind spot kept in the cumulative baseline", lambda: p.returncode == 0 and C["alerts"] == 0 and "z=N/A" in out),
  # The gated baseline with the SD floor detects the same scan.
  "constant_then_scan_tail@gated_sd_floor": ("constant-feature blind spot closed by gated baseline + SD floor", lambda: p.returncode == 0 and C["alerts"] >= 1),
}
if a.name not in CHECKS: print("no check for", a.name); sys.exit(2)
tag, fn = CHECKS[a.name]
ok = False
try: ok = bool(fn())
except Exception as e: print("  check raised", repr(e))
print("audit_check[%s] %s: %s  rc=%d t=%.2fs counters=%s max_window_packets=%s" % (
    a.name, tag, "PASS" if ok else "FAIL", p.returncode, dt, C, max((w["pc"] for w in W), default=None)))
if not ok: print(p.stderr.strip()[:300])
sys.exit(0 if ok else 1)
