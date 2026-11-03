#!/usr/bin/env python3
"""Map labels onto NetSentinel's 5-second windows (evaluation step 6-8).

usage (CICIDS2017 flows): label_windows.py --trace run.csv --flows friday.csv [--flows ...] --offset SECONDS
                          [--mixed-share 0.10] [--ts-format FMT] [--hour12-heuristic] --out windows.csv
usage (synthetic intervals): label_windows.py --trace run.csv --intervals labels.csv --out windows.csv
       (intervals CSV columns: start,end,type in PCAP epoch seconds)

Rules (fixed before any CICIDS2017 run; see docs/EVALUATION_METHODOLOGY.md):
  * A flow occupies [start + offset, start + offset + duration] in PCAP time; a zero-duration flow is a point.
  * Per window, flows overlapping it are counted: attack (label not BENIGN and not '... - Attempted'),
    attempted (an '... - Attempted' attack flow), benign.
  * Estimated packets: each flow's packets (fwd + bwd) are spread uniformly over its duration and the
    overlapping fraction is attributed to the window (point flows: all packets).
  * label = attack       if >= 1 attack flow overlaps and attack share >= --mixed-share
            mixed        if >= 1 attack flow overlaps but attack share < --mixed-share
            attempted    if only attempted (and benign) flows overlap
            benign       if only benign flows overlap
            unlabelled   if no labelled flow overlaps the window
  * attack_types = '+'-joined attack types overlapping the window.
Output columns: window_index, window_start, window_end, label, attack_types, attack_share, n_attack_flows,
n_attempted_flows, n_benign_flows. A '#' footer reports label coverage (step 8).
"""
import argparse, bisect, csv, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nslib

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trace", required=True); ap.add_argument("--flows", action="append"); ap.add_argument("--intervals")
    ap.add_argument("--offset", type=float, default=None); ap.add_argument("--mixed-share", type=float, default=0.10)
    ap.add_argument("--ts-format"); ap.add_argument("--hour12-heuristic", action="store_true"); ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if bool(a.flows) == bool(a.intervals): ap.error("give exactly one of --flows or --intervals")
    if a.flows and a.offset is None: ap.error("--flows needs --offset (measure it with align.py)")
    meta, rows = nslib.read_trace(a.trace)
    starts = [r["window_start"] for r in rows]; ends = [r["window_end"] for r in rows]
    if not rows: print("empty trace"); sys.exit(2)
    W = [{"atk": 0, "att": 0, "ben": 0, "atk_p": 0.0, "all_p": 0.0, "types": set()} for _ in rows]
    t_lo, t_hi = starts[0], ends[-1]
    n_total = n_in = n_outside = 0
    def add(s, e, kind, typ, pkts):
        nonlocal n_in
        i = max(0, bisect.bisect_right(starts, s) - 1)
        hit = False
        dur = e - s
        while i < len(rows) and starts[i] <= e:
            ws, we = starts[i], ends[i]
            ov = min(e, we) - max(s, ws)
            if ov > 0 or (dur == 0 and ws <= s < we):
                hit = True
                frac = 1.0 if dur == 0 else ov / dur
                X = W[i]; X["all_p"] += pkts * frac
                if kind == "attack": X["atk"] += 1; X["atk_p"] += pkts * frac; X["types"].add(typ)
                elif kind == "attempted": X["att"] += 1
                else: X["ben"] += 1
            i += 1
        if hit: n_in += 1
        return hit
    if a.intervals:
        with open(a.intervals, newline="") as fh:
            for r in csv.DictReader(fh):
                n_total += 1
                s, e = float(r["start"]), float(r["end"])
                if e < t_lo or s > t_hi: n_outside += 1; continue
                add(s, e, "attack", r["type"], max(1.0, e - s))
        # windows not covered by an attack interval are benign by construction in synthetic scenarios
        for X in W:
            if X["atk"] == 0: X["ben"] = 1
    else:
        tsp = nslib.TimestampParser(a.ts_format, a.hour12_heuristic)
        for f in nslib.read_flows(a.flows, tsp):
            n_total += 1
            s = f["start"] + a.offset; e = s + f["dur"]
            if e < t_lo or s > t_hi: n_outside += 1; continue
            kind = "benign" if f["benign"] else ("attempted" if f["attempted"] else "attack")
            add(s, e, kind, nslib.attack_type(f["label"]), max(1, f["pkts"]))
    counts = {}
    with open(a.out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["window_index", "window_start", "window_end", "label", "attack_types", "attack_share",
                    "n_attack_flows", "n_attempted_flows", "n_benign_flows"])
        for r, X in zip(rows, W):
            share = X["atk_p"] / X["all_p"] if X["all_p"] > 0 else (1.0 if X["atk"] else 0.0)
            if X["atk"]: lab = "attack" if share >= a.mixed_share else "mixed"
            elif X["att"]: lab = "attempted"
            elif X["ben"]: lab = "benign"
            else: lab = "unlabelled"
            counts[lab] = counts.get(lab, 0) + 1
            w.writerow([r["window_index"], "%.6f" % r["window_start"], "%.6f" % r["window_end"], lab,
                        "+".join(sorted(X["types"])), "%.4f" % share, X["atk"], X["att"], X["ben"]])
        fh.write("# label_source=%s\n" % ("intervals" if a.intervals else "flows"))
        fh.write("# offset_seconds=%s\n" % a.offset)
        fh.write("# mixed_share=%s\n" % a.mixed_share)
        fh.write("# labelled_records_total=%d\n# labelled_records_overlapping_trace=%d\n# labelled_records_outside_trace_time=%d\n"
                 % (n_total, n_in, n_outside))
        for k in ("attack", "mixed", "attempted", "benign", "unlabelled"):
            fh.write("# windows_%s=%d\n" % (k, counts.get(k, 0)))
    print("labelled records: %d total, %d overlap the trace, %d outside its time range" % (n_total, n_in, n_outside))
    print("window labels:", ", ".join("%s=%d" % (k, counts.get(k, 0)) for k in ("attack", "mixed", "attempted", "benign", "unlabelled")))

if __name__ == "__main__":
    main()
