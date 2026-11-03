#!/usr/bin/env python3
"""SD-floor experiment: choose a per-feature minimum standard deviation (SD floor) for the gated baseline (--policy gated).

usage: floor_sweep.py --exe build/netsentinel --out docs/evidence/floor_sweep   (Linux or macOS)

Design (one factor at a time, decided before running):
  * Feature i's floor is swept over a grid while the other three floors are set to 1e9, so the other
    features can never trigger and cannot cause gating. Feature i's triggers are read from the trace.
  * Benign scenarios (must give 0 triggers on feature i):
      J  near-constant host with quantised jitter: base window n=20, size 146 B, ports {80,443}, 3 dst IPs;
         every 10th window one feature moves by its natural resolution unit (n 20->21; one 146 B packet
         replaced by a 60 B ACK, i.e. avg size -4.3 B; ports 2->3; IPs 3->4). 300 windows (25 min).
      N  stationary noisy host (deterministic pseudo-random n 14..26, mixed sizes, 2-4 ports, 3-6 IPs).
         Floors far below the natural spread must not change anything here (sanity check).
  * Attack scenarios on a constant baseline (60 identical windows, one attack window, 3 normal windows);
    detected = feature i triggers in the attack window. Graded steps per feature:
      packet_count 20 -> 24, 30, 40, 1000 ; avg_packet_size 146 -> 150, 160, 200, 1000 B ;
      unique_dst_ports 2 -> 4, 6, 10, 1000 ; unique_dst_ips 3 -> 5, 7, 10, 100.
    The largest step of each feature is the constant_then_scan-type change that must be detected.
  * Selection rule: the SMALLEST grid value with (a) 0 false triggers on J, (b) no more false triggers on N
    than the gated baseline without a floor (a floor must not add alarms on ordinary noisy traffic; N's own 3-sigma alarms
    are a limitation of the z-score method, not a floor effect), and (c) detection of the largest step. Smaller floors are
    rejected because quantised jitter alarms; the graded steps show what each candidate costs.
Threshold 3.0, warm-up 20, policy gated, recovery 60 throughout. Synthetic only: no CICIDS2017 data is used
(Friday benign windows are for validation, not tuning).
"""
import argparse, csv, os, random, subprocess, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scenario_pcap as sp

FEATURES = ["packet_count", "avg_packet_size", "unique_dst_ports", "unique_dst_ips"]
GRID = {
    "packet_count":     [0.1, 0.25, 0.5, 1.0, 2.0, 3.0, 5.0],
    "avg_packet_size":  [0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0],
    "unique_dst_ports": [0.1, 0.25, 0.5, 1.0, 2.0, 3.0],
    "unique_dst_ips":   [0.1, 0.25, 0.5, 1.0, 2.0, 3.0],
}
STEPS = {
    "packet_count":     [("24", dict(n=24)), ("30", dict(n=30)), ("40", dict(n=40)), ("1000", dict(n=1000))],
    "avg_packet_size":  [("150", dict(size=150)), ("160", dict(size=160)), ("200", dict(size=200)), ("1000", dict(size=1000))],
    "unique_dst_ports": [("4", dict(ports=(80, 443, 8080, 22))), ("6", dict(ports=tuple(range(1, 7)))),
                         ("10", dict(ports=tuple(range(1, 11)))), ("1000", dict(n=1000, ports=tuple(range(1, 1001))))],
    "unique_dst_ips":   [("5", dict(ips=tuple(range(5, 10)))), ("7", dict(ips=tuple(range(5, 12)))),
                         ("10", dict(ips=tuple(range(5, 15)))), ("100", dict(n=100, ips=tuple(range(5, 105))))],
}

def benign_jitter():
    W = []
    for i in range(300):
        m = i % 10
        if m == 3: W.append(sp.window(n=21))
        elif m == 5: W.append(sp.window(small_packets=1))
        elif m == 7: W.append(sp.window(ports=(80, 443, 8080)))
        elif m == 9: W.append(sp.window(ips=(5, 6, 7, 8)))
        else: W.append(sp.window())
    return W

def benign_noisy():
    rnd = random.Random(20261031); W = []
    for i in range(300):
        n = rnd.randint(14, 26)
        sizes = [rnd.choice([60, 146, 590, 1514]) for _ in range(n)]
        ports = tuple(rnd.sample([80, 443, 8080, 22, 53], rnd.randint(2, 4)))
        ips = tuple(range(5, 5 + rnd.randint(3, 6)))
        W.append({"n": n, "sizes": sizes, "ports": list(ports), "ips": list(ips)})
    return W

def attack(kw):
    return [sp.window() for _ in range(60)] + [sp.window(**kw)] + [sp.window() for _ in range(3)]

def run(exe, pcap, floors, tmp):
    t = os.path.join(tmp, "t.csv")
    r = subprocess.run([exe, "--quiet", "--policy", "gated", "--sd-floor", "--floor-values", ",".join(str(f) for f in floors),
                        "--trace", t, pcap], capture_output=True, text=True)
    if r.returncode != 0: raise SystemExit("run failed: %s %s" % (r.returncode, r.stderr))
    rows = list(csv.DictReader(l for l in open(t) if not l.startswith("#")))
    return rows

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--exe", required=True); ap.add_argument("--out", required=True); a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True); tmp = tempfile.mkdtemp(prefix="ns_floor_")
    files = {}
    def pc(name, windows):
        p = os.path.join(tmp, name + ".pcap"); open(p, "wb").write(sp.build(windows)); files[name] = p; return p
    pc("benign_jitter", benign_jitter()); pc("benign_noisy", benign_noisy())
    for f in FEATURES:
        for label, kw in STEPS[f]: pc("attack_%s_%s" % (f, label), attack(kw))
    # no-floor reference (gated baseline without floor) on the same scenarios
    ref = []
    for i, f in enumerate(FEATURES):
        def nofloor(p):
            t = os.path.join(tmp, "n.csv")
            subprocess.run([a.exe, "--quiet", "--policy", "gated", "--trace", t, p], capture_output=True, check=False)
            return list(csv.DictReader(l for l in open(t) if not l.startswith("#")))
        rr = {"feature": f}
        for b in ("benign_jitter", "benign_noisy"):
            rr[b + "_false_triggers"] = sum(1 for r in nofloor(files[b]) if f in r["triggered_features"].split("+"))
        for label, _ in STEPS[f]:
            rr["detect_" + label] = int(f in nofloor(files["attack_%s_%s" % (f, label)])[60]["triggered_features"].split("+"))
        ref.append(rr)
    results = []; chosen = {}
    for i, f in enumerate(FEATURES):
        for eps in GRID[f]:
            floors = [1e9] * 4; floors[i] = eps
            row = {"feature": f, "floor": eps}
            for b in ("benign_jitter", "benign_noisy"):
                rows = run(a.exe, files[b], floors, tmp)
                row[b + "_false_triggers"] = sum(1 for r in rows if f in r["triggered_features"].split("+"))
            for label, _ in STEPS[f]:
                rows = run(a.exe, files["attack_%s_%s" % (f, label)], floors, tmp)
                atk = rows[60]
                row["detect_" + label] = int(f in atk["triggered_features"].split("+"))
            results.append(row)
        noisy_ref = next(r for r in ref if r["feature"] == f)["benign_noisy_false_triggers"]
        ok = [r for r in results if r["feature"] == f and r["benign_jitter_false_triggers"] == 0
              and r["benign_noisy_false_triggers"] <= noisy_ref and r["detect_" + STEPS[f][-1][0]] == 1]
        chosen[f] = min(r["floor"] for r in ok) if ok else None
    with open(os.path.join(a.out, "floor_sweep.csv"), "w", newline="") as fh:
        keys = sorted({k for r in results for k in r}, key=lambda k: (k != "feature", k != "floor", k))
        w = csv.DictWriter(fh, fieldnames=keys); w.writeheader(); w.writerows(results)
    with open(os.path.join(a.out, "floor_sweep.md"), "w") as fh:
        fh.write("# SD-floor sweep (synthetic scenarios only)\n\nGenerated by tools/experiments/floor_sweep.py; exe=%s\n\n" % a.exe)
        for f in FEATURES:
            labels = [l for l, _ in STEPS[f]]
            fh.write("## %s\n\n| floor | false triggers: jitter (300 w) | false triggers: noisy (300 w) | %s |\n|---|---|---|%s\n"
                     % (f, " | ".join("detects step to " + l for l in labels), "---|" * len(labels)))
            nofloor = next(r for r in ref if r["feature"] == f)
            fh.write("| none (gated baseline without floor) | %d | %d | %s |\n" % (nofloor["benign_jitter_false_triggers"], nofloor["benign_noisy_false_triggers"],
                     " | ".join("yes" if nofloor["detect_" + l] else "no" for l in labels)))
            for r in results:
                if r["feature"] != f: continue
                mark = " **chosen**" if r["floor"] == chosen[f] else ""
                fh.write("| %g%s | %d | %d | %s |\n" % (r["floor"], mark, r["benign_jitter_false_triggers"], r["benign_noisy_false_triggers"],
                         " | ".join("yes" if r["detect_" + l] else "no" for l in labels)))
            fh.write("\n")
        fh.write("Chosen floors (smallest grid value with 0 jitter false triggers, no extra noisy false triggers versus no floor, and detection of the largest step): %s\n" %
                 ", ".join("%s=%s" % (f, chosen[f]) for f in FEATURES))
    print("CHOSEN", ",".join(str(chosen[f]) for f in FEATURES))
    print(open(os.path.join(a.out, "floor_sweep.md")).read())

if __name__ == "__main__":
    main()
