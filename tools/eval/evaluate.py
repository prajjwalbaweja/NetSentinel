#!/usr/bin/env python3
"""Window-level and event-level metrics for one NetSentinel run (evaluation step 12).

usage: evaluate.py --trace run.csv --windows windows.csv [--name gated_sd_floor] [--json out.json]

Excluded from every metric (counted and reported): windows that were not scored (idle, no_parsed_traffic,
partial), warm-up windows, windows labelled unlabelled or attempted. 'mixed' windows are excluded from the
primary metrics and reported in a second variant where they count as attack windows.
  TP alert & attack   FP alert & benign   FN no alert & attack   TN no alert & benign
  precision = TP/(TP+FP)  recall = TP/(TP+FN)  F1  FPR = FP/(FP+TN)
  false alarms per hour = FP / (benign windows x window length / 3600)
Event level: an attack event is a maximal run of consecutive attack-or-mixed windows; it is detected if at
least one of its scored windows alerts; detection delay = start of the first alerting window - event start.
Per attack type: events and windows whose attack_types include that type.
"""
import argparse, csv, json, os, sys
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nslib

def ratio(a, b): return (a / b) if b else None

def evaluate(trace_rows, label_rows, window_sec=5.0):
    lab = {int(r["window_index"]): r for r in label_rows}
    excl = defaultdict(int); C = {"primary": defaultdict(int), "mixed_as_attack": defaultdict(int)}
    per_type = defaultdict(lambda: {"windows": 0, "windows_alerted": 0, "events": 0, "events_detected": 0,
                                    "delays_s": [], "feature_triggers": defaultdict(int)})
    usable = []
    for r in trace_rows:
        L = lab.get(r["window_index"])
        if L is None: excl["no_label_row"] += 1; continue
        if r.get("status", "scored") != "scored": excl["not_scored_" + r["status"]] += 1; continue
        if nslib.is_warmup(r): excl["warmup"] += 1; continue
        if L["label"] in ("unlabelled", "attempted"): excl["label_" + L["label"]] += 1; continue
        usable.append((r, L))
        alert = r["alert"] == 1
        for variant in ("primary", "mixed_as_attack"):
            if L["label"] == "mixed" and variant == "primary": continue
            attack = L["label"] in ("attack", "mixed")
            key = ("TP" if alert else "FN") if attack else ("FP" if alert else "TN")
            C[variant][key] += 1
        if L["label"] == "mixed": excl["mixed_in_primary"] += 1
        if L["label"] in ("attack", "mixed"):
            for t in filter(None, L["attack_types"].split("+")):
                per_type[t]["windows"] += 1
                if alert:
                    per_type[t]["windows_alerted"] += 1
                    for f in filter(None, r.get("triggered_features", "").split("+")): per_type[t]["feature_triggers"][f] += 1
    # events over ALL windows (including unscored/warm-up), so an event is not split by an idle window
    events = []; cur = None
    by_index = {r["window_index"]: r for r in trace_rows}
    for r in trace_rows:
        L = lab.get(r["window_index"])
        is_atk = L is not None and L["label"] in ("attack", "mixed")
        if is_atk:
            if cur is None: cur = {"start": r["window_start"], "rows": [], "types": set()}
            cur["rows"].append(r); cur["types"].update(filter(None, L["attack_types"].split("+")))
        elif cur is not None:
            events.append(cur); cur = None
    if cur is not None: events.append(cur)
    ev_summary = []
    for e in events:
        scored = [r for r in e["rows"] if r.get("status", "scored") == "scored" and not nslib.is_warmup(r)]
        alerted = [r for r in scored if r["alert"] == 1]
        det = bool(alerted); delay = (alerted[0]["window_start"] - e["start"]) if alerted else None
        ev_summary.append({"start": e["start"], "end": e["rows"][-1]["window_end"], "windows": len(e["rows"]),
                           "scored_windows": len(scored), "types": sorted(e["types"]), "detected": det,
                           "delay_s": delay})
        for t in e["types"]:
            per_type[t]["events"] += 1
            if det: per_type[t]["events_detected"] += 1; per_type[t]["delays_s"].append(delay)
    def metrics(c, benign_windows):
        TP, FP, FN, TN = c["TP"], c["FP"], c["FN"], c["TN"]
        p, rc = ratio(TP, TP + FP), ratio(TP, TP + FN)
        f1 = (2 * p * rc / (p + rc)) if p and rc else (0.0 if p is not None and rc is not None else None)
        hours = benign_windows * window_sec / 3600.0
        return {"TP": TP, "FP": FP, "FN": FN, "TN": TN, "precision": p, "recall": rc, "f1": f1,
                "fpr": ratio(FP, FP + TN), "benign_hours": round(hours, 4), "false_alarms_per_hour": ratio(FP, hours)}
    out = {"windows_total": len(trace_rows), "windows_usable": len(usable), "excluded": dict(excl),
           "primary": metrics(C["primary"], C["primary"]["FP"] + C["primary"]["TN"]),
           "mixed_as_attack": metrics(C["mixed_as_attack"], C["mixed_as_attack"]["FP"] + C["mixed_as_attack"]["TN"]),
           "events": ev_summary,
           "per_attack_type": {t: {"windows": v["windows"], "windows_alerted": v["windows_alerted"],
                                   "window_recall": ratio(v["windows_alerted"], v["windows"]),
                                   "events": v["events"], "events_detected": v["events_detected"],
                                   "median_delay_s": (sorted(v["delays_s"])[len(v["delays_s"]) // 2] if v["delays_s"] else None),
                                   "feature_triggers": dict(v["feature_triggers"])} for t, v in sorted(per_type.items())}}
    return out

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trace", required=True); ap.add_argument("--windows", required=True)
    ap.add_argument("--name", default="run"); ap.add_argument("--json")
    a = ap.parse_args()
    meta, rows = nslib.read_trace(a.trace)
    with open(a.windows, newline="") as fh:
        labels = list(csv.DictReader(l for l in fh if not l.startswith("#")))
    res = evaluate(rows, labels, float(meta.get("window_sec", 5)))
    res["name"] = a.name; res["trace_meta"] = meta
    if a.json:
        with open(a.json, "w") as fh: json.dump(res, fh, indent=2)
    m = res["primary"]
    print("[%s] usable windows %d of %d; TP %d FP %d FN %d TN %d; precision %s recall %s F1 %s FPR %s; false alarms/h %s"
          % (a.name, res["windows_usable"], res["windows_total"], m["TP"], m["FP"], m["FN"], m["TN"],
             fmt(m["precision"]), fmt(m["recall"]), fmt(m["f1"]), fmt(m["fpr"]), fmt(m["false_alarms_per_hour"])))

def fmt(x): return "n/a" if x is None else ("%.4f" % x)

if __name__ == "__main__":
    main()
