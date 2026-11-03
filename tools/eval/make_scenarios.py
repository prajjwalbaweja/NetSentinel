#!/usr/bin/env python3
"""Labelled synthetic scenarios for the configuration comparison (supplement, never a replacement for CICIDS2017).

usage: make_scenarios.py OUT_DIR
Writes, per scenario, OUT_DIR/<name>.pcap and OUT_DIR/<name>_labels.csv (start,end,type in PCAP epoch s).
Benign traffic is pseudo-random but deterministic (fixed seeds): 16..26 packets per 5 s window, mixed frame
sizes, 2..4 destination ports, 3..6 destination IPs. Windows are aligned to the detector's grid.
  s1_step              120 benign, 10 attack windows (2.5x packets, +20 scanned ports), 60 benign
  s2_sustained         60 benign, 100 attack windows (3x packets flood), 40 benign   -> absorption (recovery limit)
  s3_slow_ramp         60 benign, 120 windows ramping packets +2% per window (labelled attack), 40 benign (method limitation: slow ramps)
  s4_legit_shift       120 benign, then a PERMANENT legitimate 1.5x volume shift for 200 windows (labelled
                       benign): measures false alarms caused by lockout (gated baseline) versus absorption (cumulative baseline)
  s5_idle_gap          60 benign, 10 min silence, 40 benign, 5 attack windows (scan), 20 benign (idle windows, idle-gap cap)
  s6_quiet_host_scan   120 windows of a near-constant host (rare +-1 jitter), 1 window port scan (100 ports),
                       20 benign (the SD floor's purpose)
"""
import csv, os, random, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "experiments"))
import scenario_pcap as sp

T0 = 1_499_420_000.0   # an epoch in July 2017, so timestamps look like the dataset's era

def benign(rnd, scale=1.0):
    n = max(1, int(round(rnd.randint(16, 26) * scale)))
    return {"n": n, "sizes": [rnd.choice([60, 66, 146, 590, 1514]) for _ in range(n)],
            "ports": rnd.sample([80, 443, 8080, 22, 53], rnd.randint(2, 4)), "ips": list(range(5, 5 + rnd.randint(3, 6)))}

def write(out, name, windows, attacks, t0=T0):
    """windows: list of window specs or ('gap', seconds). attacks: list of (first_window_pos, last_window_pos, type)."""
    data = bytearray(sp.HDR); t = t0; pos_time = []
    for w in windows:
        if isinstance(w, tuple) and w[0] == "gap":
            t += w[1]; pos_time.append(None); continue
        pos_time.append(t)
        data += sp.build([w], t0=t)[24:]
        t += 5.0
    open(os.path.join(out, name + ".pcap"), "wb").write(bytes(data))
    with open(os.path.join(out, name + "_labels.csv"), "w", newline="") as fh:
        wr = csv.writer(fh); wr.writerow(["start", "end", "type"])
        for a, b, typ in attacks:
            wr.writerow(["%.6f" % pos_time[a], "%.6f" % (pos_time[b] + 5.0), typ])

def main():
    if len(sys.argv) != 2: print(__doc__); sys.exit(2)
    out = sys.argv[1]; os.makedirs(out, exist_ok=True)
    r = random.Random(1)
    W = [benign(r) for _ in range(120)]
    for _ in range(10):
        w = benign(r, 2.5); w["ports"] = w["ports"] + list(range(1000, 1020)); W.append(w)
    W += [benign(r) for _ in range(60)]
    write(out, "s1_step", W, [(120, 129, "step_scan")])
    r = random.Random(2)
    W = [benign(r) for _ in range(60)] + [benign(r, 3.0) for _ in range(100)] + [benign(r) for _ in range(40)]
    write(out, "s2_sustained", W, [(60, 159, "sustained_flood")])
    r = random.Random(3)
    W = [benign(r) for _ in range(60)] + [benign(r, 1.02 ** (k + 1)) for k in range(120)] + [benign(r) for _ in range(40)]
    write(out, "s3_slow_ramp", W, [(60, 179, "slow_ramp")])
    r = random.Random(4)
    W = [benign(r) for _ in range(120)] + [benign(r, 1.5) for _ in range(200)]
    write(out, "s4_legit_shift", W, [])
    r = random.Random(5)
    W = [benign(r) for _ in range(60)] + [("gap", 600.0)] + [benign(r) for _ in range(40)]
    for _ in range(5):
        w = benign(r); w["n"] = 60; w["sizes"] = [60]; w["ports"] = list(range(1, 61)); W.append(w)
    W += [benign(r) for _ in range(20)]
    write(out, "s5_idle_gap", W, [(101, 105, "scan_after_gap")])
    r = random.Random(6)
    W = []
    for i in range(120):
        w = sp.window()
        if i % 17 == 5: w = sp.window(n=21)
        if i % 23 == 11: w = sp.window(ips=(5, 6, 7, 8))
        W.append(w)
    W.append(sp.window(n=100, ports=tuple(range(1, 101)), size=60))
    W += [sp.window() for _ in range(20)]
    write(out, "s6_quiet_host_scan", W, [(120, 120, "quiet_host_scan")])
    print("scenarios written to", out)

if __name__ == "__main__":
    main()
