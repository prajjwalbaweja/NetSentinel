#!/usr/bin/env python3
"""Self-tests for tools/eval (run by CTest as eval_tools). usage: test_eval_tools.py --exe EXE --root ROOT
1. evaluator on a hand-labelled toy trace with known answers;
2. original-prototype console parser on that version's sample.pcap output;
3. end-to-end on the CICFlowMeter-format STAND-IN (not CICIDS2017 data): offset recovery, flow-to-window
   labelling, metrics, comparison runner."""
import argparse, csv, json, os, subprocess, sys, tempfile
ap = argparse.ArgumentParser(); ap.add_argument("--exe", required=True); ap.add_argument("--root", required=True); a = ap.parse_args()
root = os.path.abspath(a.root); tools = os.path.join(root, "tools", "eval"); sys.path.insert(0, tools)
import nslib, evaluate
fails = []
def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  " + str(detail)))
    if not cond: fails.append(name)

# ---- 1. toy evaluator case: 12 windows, known labels and alerts
def row(i, status="scored", alert=0, warm=False, trig=""):
    z = "warmup" if warm else "0.1"
    return {"window_index": i, "window_start": 100.0 + 5 * i, "window_end": 105.0 + 5 * i, "status": status, "alert": alert,
            "triggered_features": trig, "z_packet_count": z, "z_avg_packet_size": z, "z_unique_dst_ports": z, "z_unique_dst_ips": z}
T = [row(0, warm=True), row(1, warm=True, alert=0), row(2), row(3, alert=1, trig="packet_count"),       # 3: FP
     row(4), row(5, alert=1, trig="unique_dst_ports"), row(6, alert=0), row(7, alert=1, trig="packet_count"),  # 5 TP, 6 FN(attack), 7 TP
     row(8, status="idle"), row(9, alert=1), row(10), row(11, status="partial")]
labels = ["benign", "benign", "benign", "benign", "attack", "attack", "attack", "attack", "attack", "mixed", "unlabelled", "benign"]
L = [{"window_index": str(i), "label": l, "attack_types": ("X" if l in ("attack", "mixed") else "")} for i, l in enumerate(labels)]
r = evaluate.evaluate(T, L)
p = r["primary"]
check("toy: confusion TP=2 FP=1 FN=2 TN=1", (p["TP"], p["FP"], p["FN"], p["TN"]) == (2, 1, 2, 1), p)
# window 4 is an attack window without alert (FN), 6 FN; 8 idle excluded; 9 mixed excluded in primary; 10 unlabelled excluded
check("toy: exclusions counted", r["excluded"].get("warmup") == 2 and r["excluded"].get("not_scored_idle") == 1
      and r["excluded"].get("not_scored_partial") == 1 and r["excluded"].get("label_unlabelled") == 1, r["excluded"])
check("toy: precision/recall", abs(p["precision"] - 2 / 3) < 1e-12 and abs(p["recall"] - 0.5) < 1e-12)
check("toy: false alarms per hour = 1 FP / (2 benign windows x 5 s)", abs(p["false_alarms_per_hour"] - 360.0) < 1e-9, p["false_alarms_per_hour"])
m = r["mixed_as_attack"]
check("toy: mixed counted as attack in second variant", (m["TP"], m["FN"]) == (3, 2), m)
ev = r["events"]
check("toy: one event spanning windows 4-9, detected, delay 5 s", len(ev) == 1 and ev[0]["windows"] == 6 and ev[0]["detected"]
      and abs(ev[0]["delay_s"] - 5.0) < 1e-9, ev)
check("toy: per-type feature triggers", r["per_attack_type"]["X"]["feature_triggers"] == {"unique_dst_ports": 1, "packet_count": 1},
      r["per_attack_type"]["X"])

# ---- 2. original-prototype console parser
rows = nslib.prototype_console_to_rows(open(os.path.join(root, "tests/eval/data/prototype_sample_console.txt")).read())
check("original-prototype parser: 30 windows, one alert at window 25, 20 warm-up windows",
      len(rows) == 30 and [x["window_index"] for x in rows if x["alert"]] == [25] and sum(nslib.is_warmup(x) for x in rows) == 20)

# ---- 3. stand-in end to end
tmp = tempfile.mkdtemp(prefix="ns_eval_")
def py(*args): return subprocess.run([sys.executable, *args], capture_output=True, text=True)
g = py(os.path.join(tools, "make_cicids_standin.py"), tmp)
check("stand-in generated", g.returncode == 0, g.stderr)
al = py(os.path.join(tools, "align.py"), "--pcap", os.path.join(tmp, "standin.pcap"), "--labels", os.path.join(tmp, "standin_flows.csv"),
        "--out", os.path.join(tmp, "offset.json"))
off = json.load(open(os.path.join(tmp, "offset.json")))["offset_seconds"] if al.returncode == 0 else None
check("align recovers the hidden +3 h offset within label resolution (1 s)", off is not None and abs(off - 10800) <= 1.0, (al.returncode, off, al.stdout[-300:]))
res = os.path.join(tmp, "res")
rc = py(os.path.join(tools, "run_comparison.py"), "--exe", a.exe, "--pcap", os.path.join(tmp, "standin.pcap"),
        "--flows", os.path.join(tmp, "standin_flows.csv"), "--offset", str(off or 10800), "--out", res, "--no-hash")
check("comparison runner completes", rc.returncode == 0, rc.stderr[-500:])
if rc.returncode == 0:
    M = {x["name"]: x for x in json.load(open(os.path.join(res, "metrics.json")))}
    check("all four configurations ran", set(M) == {"cumulative", "gated", "gated_sd_floor", "frozen"}, set(M))
    lab = list(csv.DictReader(l for l in open(os.path.join(res, "cumulative.windows.csv")) if not l.startswith("#")))
    atk = [float(x["window_start"]) for x in lab if x["label"] == "attack"]
    t0 = float(lab[0]["window_start"])
    check("attack windows fall inside the scripted PortScan (12-14 min) and DDoS (20-24 min) intervals",
          atk and all((715 <= t - t0 <= 845) or (1195 <= t - t0 <= 1445) for t in atk), [round(t - t0) for t in atk[:5]])
    check("'Attempted' flows produce attempted windows, excluded from metrics",
          any(x["label"] == "attempted" for x in lab) and M["cumulative"]["excluded"].get("label_attempted", 0) > 0)
    check("both attack types detected as events by gated_sd_floor",
          all(M["gated_sd_floor"]["per_attack_type"][t]["events_detected"] == 1 for t in ("PortScan", "DDoS")), M["gated_sd_floor"]["per_attack_type"])
    check("summary.md and environment.txt written", os.path.exists(os.path.join(res, "summary.md")) and
          "exe_sha256=" in open(os.path.join(res, "environment.txt")).read())
sys.exit(1 if fails else 0)
