#!/usr/bin/env python3
"""Checks of command-line handling and the per-window CSV trace. usage: check_cli_trace.py --exe EXE --root ROOT"""
import sys, os, csv, subprocess, argparse, tempfile, math
ap = argparse.ArgumentParser(); ap.add_argument("--exe", required=True); ap.add_argument("--root", required=True); a = ap.parse_args()
root = os.path.abspath(a.root); tmp = tempfile.mkdtemp(prefix="ns_cli_")
def run(*args): return subprocess.run([a.exe, *args], cwd=root, capture_output=True, text=True)
def trace(path):
    meta, rows = {}, []
    lines = open(path).read().splitlines()
    for l in lines:
        if l.startswith("# ") and "=" in l: k, v = l[2:].split("=", 1); meta[k] = v
    body = [l for l in lines if not l.startswith("#")]
    rows = list(csv.DictReader(body))
    return meta, rows
fails = []
def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  " + str(detail)))
    if not cond: fails.append(name)

check("--help exits 0", run("--help").returncode == 0)
for bad in (["--bogus"], ["--threshold", "abc"], ["--threshold", "-1"], ["--gap-cap", "1"], ["--trace"], ["a.pcap", "b.pcap"],
            ["--policy", "b2"], ["--sd-floor"], ["--policy", "frozen", "--sd-floor"], ["--recovery", "0"],
            ["--recovery", "2.5"], ["--floor-values", "1,2,3"], ["--floor-values", "1,2,0,4"]):
    r = run(*bad); check("invalid %s exits 64 with usage" % bad, r.returncode == 64 and "usage:" in r.stderr, r.returncode)

t = os.path.join(tmp, "s.csv")
plain = run("data/sample.pcap"); traced = run("--trace", t, "data/sample.pcap")
check("console identical with and without --trace", plain.stdout == traced.stdout)
meta, rows = trace(t)
check("trace has one row per emitted window", len(rows) == int(meta["windows_emitted"]) == 30, (len(rows), meta.get("windows_emitted")))
check("trace footer run_status clean_eof", meta.get("run_status") == "clean_eof")
check("trace alerts match footer", sum(int(r["alert"]) for r in rows) == int(meta["alerts"]) == 1)
check("trace header records configuration", meta.get("threshold") == "3" and meta.get("gap_cap_sec") == "60" and "policy" in meta)

# Trace golden for sample.pcap: integer/text columns exact, floats within rel 2e-5.
gm, grows = trace(os.path.join(root, "tests/golden/sample_original.trace.csv"))
ok = len(grows) == len(rows)
for g, r in zip(grows, rows):
    for k in g:
        x, y = g[k], r[k]
        if x == y: continue
        try:
            fx, fy = float(x), float(y); ok &= abs(fx - fy) <= 2e-5 * max(1.0, abs(fx))
        except ValueError: ok = False
check("sample trace matches golden tests/golden/sample_original.trace.csv", ok)

t2 = os.path.join(tmp, "m.csv"); r = run("--trace", t2, "tests/data/synthetic/trunc_mid.pcap"); meta2, rows2 = trace(t2)
check("read error: exit 2 and trace run_status=read_error, last window partial",
      r.returncode == 2 and meta2.get("run_status") == "read_error" and rows2[-1]["status"] == "partial")

r = run("--threshold", "100", "data/sample.pcap")
check("--threshold 100 removes the sample alert", r.returncode == 0 and "Alerts raised:                           0" in r.stdout)
r = run("--quiet", "data/sample.pcap")
check("--quiet prints the alert and the summary only", r.stdout.count("Window ") == 1 and "Run summary" in r.stdout)
t3 = os.path.join(tmp, "gated.csv"); r = run("--policy", "gated", "--sd-floor", "--trace", t3, "data/sample.pcap"); meta3, rows3 = trace(t3)
check("gated trace header records policy, recovery and floors",
      meta3.get("policy") == "gated" and meta3.get("recovery_windows") == "60" and meta3.get("sd_floor") == "on"
      and meta3.get("sd_floor_values") == "0.5,2,0.5,0.5", meta3)
check("gated baseline gates the sample attack window", rows3[25]["alert"] == "1" and rows3[25]["baseline_action"] == "gated")
check("default policy recorded as cumulative", meta.get("policy") == "cumulative", meta.get("policy"))
# Legacy policy names b0 / b1 are accepted as aliases and give byte-identical output to the new names.
for new, old in (("cumulative", "b0"), ("gated", "b1")):
    tn, to = os.path.join(tmp, new + "_n.csv"), os.path.join(tmp, new + "_o.csv")
    rn, ro = run("--policy", new, "--trace", tn, "data/sample.pcap"), run("--policy", old, "--trace", to, "data/sample.pcap")
    check("legacy alias --policy %s behaves exactly like --policy %s" % (old, new),
          rn.returncode == ro.returncode == 0 and rn.stdout == ro.stdout and open(tn).read() == open(to).read())
sys.exit(1 if fails else 0)
