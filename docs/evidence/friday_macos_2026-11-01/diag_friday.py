import csv, json, os, sys, time
from collections import Counter
D = sys.argv[1]
NB_OFFSET = -3 * 3600
def load(name):
    body = [l for l in open(os.path.join(D, name + ".trace.csv")) if not l.startswith("#")]
    rows = list(csv.DictReader(body))
    with open(os.path.join(D, name + ".windows.csv")) as fh:
        labs = {int(r["window_index"]): r for r in csv.DictReader(l for l in fh if not l.startswith("#"))}
    return rows, labs
def clock(ts):
    return time.strftime("%H:%M:%S", time.gmtime(float(ts) + NB_OFFSET))
M = {r["name"]: r for r in json.load(open(os.path.join(D, "metrics.json")))}
print("=== 1. Feature triggers inside attack windows ===")
for cfg in [c for c in ("b0", "b1_floor", "b1_floor_r12") if c in M]:
    for t, v in M[cfg]["per_attack_type"].items():
        print("  %-13s %-9s %s" % (cfg, t, v["feature_triggers"]))
print("\n=== 2. False-positive structure ===")
for cfg in [c for c in ("b0", "b1_nofloor", "b1_floor_r12") if c in M]:
    rows, labs = load(cfg)
    runs, cur, fp_hours, gated_fp = [], 0, Counter(), 0
    for r in rows:
        L = labs.get(int(r["window_index"]))
        is_fp = (r["status"] == "scored" and r["z_packet_count"] != "warmup" and L and L["label"] == "benign" and r["alert"] == "1")
        if is_fp:
            cur += 1; fp_hours[clock(r["window_start"])[:2]] += 1
            if r.get("baseline_action") == "gated": gated_fp += 1
        elif cur:
            runs.append(cur); cur = 0
    if cur: runs.append(cur)
    lr = [x for x in runs if x >= 10]
    print("  %-13s FP %4d in %4d runs; longest %3d; runs>=10: %3d covering %4d FP; FP while gated: %d"
          % (cfg, sum(runs), len(runs), max(runs) if runs else 0, len(lr), sum(lr), gated_fp))
    print("  %-13s FP by local hour (UTC-3): %s" % ("", dict(sorted(fp_hours.items()))))
print("\n=== 3. Around the DDoS event ===")
ev = [e for e in M["b0"]["events"] if "DDoS" in e["types"]]
if ev:
    start = ev[0]["start"]
    print("  DDoS start %s, %d windows" % (clock(start), ev[0]["windows"]))
    for cfg in [c for c in ("b0", "b1_floor", "b1_floor_r12") if c in M]:
        rows, _ = load(cfg)
        idx = next(i for i, r in enumerate(rows) if float(r["window_start"]) >= start)
        cells = []
        for k in (-1, 0, 5, 12, 30, 60, 61, 120, 200):
            if 0 <= idx + k < len(rows):
                r = rows[idx + k]
                cells.append("%+d:z=%s,a=%s,%s" % (k, r["z_packet_count"][:6], r["alert"], r.get("baseline_action", "")[:7]))
        print("  %-13s %s" % (cfg, "  ".join(cells)))
