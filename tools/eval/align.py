#!/usr/bin/env python3
"""Measure the time offset between a CICIDS2017 label CSV and its PCAP (evaluation step 5).

usage: align.py --pcap Friday-WorkingHours.pcap --labels friday.csv [--labels more.csv ...]
                [--max-packets 3000000] [--ts-format FMT] [--hour12-heuristic] [--out offset.json]

Method: label timestamps are naive wall-clock times; PCAP timestamps are epoch seconds. For every labelled
flow with a full 5-tuple, the first PCAP packet with the same (proto, src, dst, sport, dport) after... any
time is a candidate match; the difference pcap_ts - label_ts is recorded. A correct offset shows up as one
dominant cluster (label timestamps have second or minute resolution, so the cluster has some width).
The tool reports the median of the dominant cluster, its spread, the number of matches, and the share of
matches inside +/- 120 s of the median. It refuses to report an offset (exit 3) if fewer than 20 matches
fall in the dominant cluster or the cluster holds less than 50% of matches; inspect the histogram then.
"""
import argparse, json, os, statistics, sys
from collections import Counter, defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nslib

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap", required=True); ap.add_argument("--labels", required=True, action="append")
    ap.add_argument("--max-packets", type=int, default=3000000); ap.add_argument("--max-flows", type=int, default=200000)
    ap.add_argument("--ts-format"); ap.add_argument("--hour12-heuristic", action="store_true"); ap.add_argument("--out")
    a = ap.parse_args()
    tsp = nslib.TimestampParser(a.ts_format, a.hour12_heuristic)
    flows = defaultdict(list); nflows = 0
    for f in nslib.read_flows(a.labels, tsp):
        if None in (f["src"], f["dst"], f["sport"], f["dport"], f["proto"]): continue
        flows[(f["proto"], f["src"], f["dst"], f["sport"], f["dport"])].append(f["start"])
        nflows += 1
        if nflows >= a.max_flows: break
    if not flows: print("no flows with a full 5-tuple in the label CSV"); sys.exit(2)
    print("label flows indexed: %d (distinct 5-tuples %d); timestamp format detected: %s" % (nflows, len(flows), tsp.fmt))
    seen = set(); diffs = []; npk = 0
    for ts, proto, src, dst, sp, dp in nslib.pcap_packets(a.pcap, a.max_packets):
        npk += 1
        key = (proto, src, dst, sp, dp)
        if key in seen or key not in flows: continue
        seen.add(key)
        # first packet of this 5-tuple in the PCAP vs the earliest labelled flow with that 5-tuple
        diffs.append(ts - min(flows[key]))
    print("pcap packets scanned: %d; 5-tuples matched: %d" % (npk, len(diffs)))
    if not diffs: print("NO MATCHES: check that the CSV belongs to this PCAP"); sys.exit(3)
    hist = Counter(int(round(d / 1800.0)) * 0.5 for d in diffs)   # half-hour bins, in hours
    print("histogram of (pcap - label) in hours (half-hour bins), top 6:")
    for h, c in hist.most_common(6): print("   %+6.1f h : %d" % (h, c))
    top_h = hist.most_common(1)[0][0]
    cluster = [d for d in diffs if abs(d - top_h * 3600) <= 1800]
    med = statistics.median(cluster)
    within = [d for d in diffs if abs(d - med) <= 120]
    share = len(within) / len(diffs)
    spread = (min(cluster) - med, max(cluster) - med)
    result = {"offset_seconds": round(med, 3), "matches": len(diffs), "cluster_matches": len(cluster),
              "share_within_120s": round(share, 3), "cluster_spread_s": [round(spread[0], 1), round(spread[1], 1)],
              "pcap_packets_scanned": npk, "timestamp_format": tsp.fmt, "hour12_heuristic": a.hour12_heuristic,
              "pcap": os.path.basename(a.pcap), "labels": [os.path.basename(x) for x in a.labels]}
    print(json.dumps(result, indent=2))
    ok = len(cluster) >= 20 and len(cluster) / len(diffs) >= 0.5
    if a.out:
        with open(a.out, "w") as fh: json.dump(dict(result, accepted=ok), fh, indent=2)
    if not ok:
        print("OFFSET NOT ACCEPTED: dominant cluster too small or not dominant. Do not proceed; inspect the histogram "
              "(a second cluster 12 h away suggests AM/PM-less timestamps: retry with --hour12-heuristic).")
        sys.exit(3)
    print("OFFSET ACCEPTED: %.3f s (%+.3f h). Use: --offset %.3f" % (med, med / 3600.0, med))

if __name__ == "__main__":
    main()
