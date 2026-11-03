#!/usr/bin/env python3
"""usage: oracle_crosscheck.py --exe EXE --root REPO_ROOT (--name GOLDEN_NAME | --pcap REL_PATH)
Runs the app on a fixture and compares EVERY window's status, printed feature values, z-scores,
warm-up/N-A state and alert (window + triggered features) with tests/oracle/oracle.py.
Tolerance: rel 1e-4 on z, rel 1e-5 on features."""
import sys, os, re, subprocess, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import oracle
ap = argparse.ArgumentParser(); ap.add_argument("--exe", required=True); ap.add_argument("--root", required=True)
ap.add_argument("--name"); ap.add_argument("--pcap"); a = ap.parse_args(); root = os.path.abspath(a.root)
if a.pcap: pcap = a.pcap; label = a.pcap
else:
    rows = [l.rstrip("\n").split("\t") for l in open(os.path.join(root, "tests/golden/MANIFEST.tsv")) if l.strip() and not l.startswith("#")]
    pcap = next(r for r in rows if r[0] == a.name)[1]; label = a.name
p = subprocess.run([a.exe, pcap], cwd=root, capture_output=True, text=True)
out = p.stdout.replace("\r\n", "\n").split("\n")
W = {}; cur = None; app_alerts = {}
wre = re.compile(r"^Window (\d+) \[([\d.]+)s - ([\d.]+)s\): packet_count=(\S+) avg_packet_size=(\S+) unique_dst_ports=(\S+) unique_dst_ips=(\S+)$")
sre = re.compile(r"^Window (\d+) \[([\d.]+)s - ([\d.]+)s\): (idle|no parsed IPv4 traffic|partial final window)")
zre = re.compile(r"^\s+(packet_count|avg_packet_size|unique_dst_ports|unique_dst_ips): (.*)$")
are = re.compile(r"^\s+!! ANOMALY\s+window"); tre = re.compile(r"^\s+- (\w+): observed=(\S+)\s+z=(\S+)$")
SMAP = {"idle": "idle", "no parsed IPv4 traffic": "no_parsed_traffic", "partial final window": "partial"}
for l in out:
    m = wre.match(l)
    if m: cur = int(m.group(1)); W[cur] = {"s": "scored", "f": [float(m.group(i)) for i in (4, 5, 6, 7)], "z": {}}; continue
    m = sre.match(l)
    if m: cur = int(m.group(1)); W[cur] = {"s": SMAP[m.group(4)], "f": None, "z": {}}; continue
    m = zre.match(l)
    if m and cur is not None: W[cur]["z"][m.group(1)] = m.group(2).strip(); continue
    if are.match(l): app_alerts[cur] = {}; continue
    m = tre.match(l)
    if m and cur in app_alerts: app_alerts[cur][m.group(1)] = float(m.group(3))
lt, pk = oracle.read(os.path.join(root, pcap))
V = oracle.windows(pk, lt); Z, alerts = oracle.score(V)
errs = []; zc = 0; na = 0; maxd = 0.0
if len(W) != len(V): errs.append("window count app=%d oracle=%d" % (len(W), len(V)))
for w in range(min(len(W), len(V))):
    so, vo = V[w]
    if W[w]["s"] != so: errs.append("W%d status app=%s oracle=%s" % (w, W[w]["s"], so)); continue
    if so == "partial":
        continue
    if so != "scored": continue
    for k, nm in enumerate(oracle.NAMES):
        fa, fo = W[w]["f"][k], vo[k]
        if abs(fa - fo) > 1e-5 * max(1.0, abs(fo)): errs.append("W%d feature %s app=%s oracle=%s" % (w, nm, fa, fo))
        s = W[w]["z"].get(nm, "<missing>"); zo = Z[w][k]
        if zo is None:
            if s.startswith("warming up") or s.startswith("z=N/A"): na += 1
            else: errs.append("W%d %s oracle=None app=%s" % (w, nm, s))
        elif not s.startswith("z="): errs.append("W%d %s oracle=%.6g app=%s" % (w, nm, zo, s))
        else:
            d = abs(float(s[2:]) - zo) / max(1.0, abs(zo)); maxd = max(maxd, d); zc += 1
            if d > 1e-4: errs.append("W%d %s z app=%s oracle=%.6g" % (w, nm, s, zo))
if set(app_alerts) != set(alerts): errs.append("alert windows app=%s oracle=%s" % (sorted(app_alerts), sorted(alerts)))
else:
    for w in alerts:
        if set(app_alerts[w]) != set(alerts[w]): errs.append("W%d triggered features app=%s oracle=%s" % (w, sorted(app_alerts[w]), sorted(alerts[w])))
print("oracle_crosscheck[%s]: windows=%d z_compared=%d warming/N-A_agreed=%d max_rel_diff=%.2e alerts app=%s oracle=%s"
      % (label, len(W), zc, na, maxd, sorted(app_alerts), sorted(alerts)))
for e in errs[:15]: print("  MISMATCH", e)
sys.exit(1 if errs or p.returncode not in (0, 2) else 0)
