#!/usr/bin/env python3
"""Scripted, reproducible comparison of the detector configurations on one PCAP.

usage (CICIDS2017 Friday):
  run_comparison.py --exe build/netsentinel --pcap Friday-WorkingHours.pcap \
      --flows friday_corrected.csv --offset <from align.py> --out results/friday \
      [--prototype-exe ../original-prototype/build/netsentinel] [--with-sensitivity] [--repo .] [--no-hash]
usage (synthetic scenario):
  run_comparison.py --exe build/netsentinel --pcap s.pcap --intervals s_labels.csv --out results/s

Configurations, identical input, windows, warm-up (20) and threshold (3.0):
  original_prototype         original prototype binary, commit f0e39c0 (historical reference, only with
                             --prototype-exe; parsed from its console)
  cumulative                 original cumulative baseline inside the corrected pipeline
  gated                      gated cumulative baseline (recovery 60) without SD floor
  gated_sd_floor             gated cumulative baseline (recovery 60) with the SD floor
  frozen                     fixed-threshold comparator (warm-up thresholds frozen)
  gated_sd_floor_recovery12  same as gated_sd_floor with recovery 12 (only with --with-sensitivity)
Results produced before 3 Nov 2026 use the older row names r0_raw, b0, b1_nofloor, b1_floor, frozen and
b1_floor_r12 for the same six configurations (docs/GLOSSARY.md).
For each: wall time, packets/s, MB/s and peak resident memory of the detector process, console log,
trace, window labels and metrics. Writes OUT/summary.md, OUT/metrics.json, OUT/environment.txt.
Nothing is tuned here; every configuration uses the defaults recorded in its trace header.
"""
import argparse, hashlib, json, os, platform, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nslib, evaluate

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIGS = [("cumulative", ["--policy", "cumulative"]), ("gated", ["--policy", "gated"]),
           ("gated_sd_floor", ["--policy", "gated", "--sd-floor"]), ("frozen", ["--policy", "frozen"])]
PROTOTYPE = "original_prototype"

def measured_run(cmd, stdout_path):
    """Runs cmd, stdout to a file. Returns (exit_code, wall_s, peak_rss_bytes, stderr)."""
    with open(stdout_path, "w") as out:
        t0 = time.perf_counter()
        p = subprocess.Popen(cmd, stdout=out, stderr=subprocess.PIPE, text=True)
        err = p.stderr.read()
        _, status, ru = os.wait4(p.pid, 0)
        wall = time.perf_counter() - t0
    p.returncode = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else (status >> 8)
    rss = ru.ru_maxrss if sys.platform == "darwin" else ru.ru_maxrss * 1024
    return p.returncode, wall, rss, err

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""): h.update(b)
    return h.hexdigest()

def write_pseudo_trace(rows, path, meta):
    cols = ["window_index", "window_start", "window_end", "status", "packet_count", "z_packet_count", "z_avg_packet_size",
            "z_unique_dst_ports", "z_unique_dst_ips", "alert", "triggered_features"]
    with open(path, "w") as fh:
        fh.write("# format=netsentinel-trace-v1 (converted from the original prototype's console output)\n")
        for k, v in meta.items(): fh.write("# %s=%s\n" % (k, v))
        fh.write(",".join(cols) + "\n")
        for r in rows: fh.write(",".join(str(r.get(c, "")) for c in cols) + "\n")

def linkage(exe):
    try:
        cmd = ["otool", "-L", exe] if sys.platform == "darwin" else ["ldd", exe]
        out = subprocess.run(cmd, capture_output=True, text=True).stdout
        return "\n".join(l.strip() for l in out.splitlines() if "pcap" in l) or "(no libpcap line found)"
    except FileNotFoundError:
        return "(otool/ldd not available)"

def fmt(x, nd=4):
    return "n/a" if x is None else (("%." + str(nd) + "f") % x if isinstance(x, float) else str(x))

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exe", required=True); ap.add_argument("--pcap", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--flows", action="append"); ap.add_argument("--offset", type=float); ap.add_argument("--intervals")
    ap.add_argument("--prototype-exe", "--r0-exe", dest="prototype_exe"); ap.add_argument("--with-sensitivity", action="store_true"); ap.add_argument("--repo")
    ap.add_argument("--no-hash", action="store_true"); ap.add_argument("--mixed-share", type=float, default=0.10)
    ap.add_argument("--ts-format"); ap.add_argument("--hour12-heuristic", action="store_true")
    a = ap.parse_args()
    if bool(a.flows) == bool(a.intervals): ap.error("give exactly one of --flows (with --offset) or --intervals")
    if a.flows and a.offset is None: ap.error("--flows needs --offset from align.py")
    os.makedirs(a.out, exist_ok=True)
    exe = os.path.abspath(a.exe); pcap = os.path.abspath(a.pcap)
    size = os.path.getsize(pcap)
    configs = list(CONFIGS)
    if a.with_sensitivity: configs.append(("gated_sd_floor_recovery12", ["--policy", "gated", "--sd-floor", "--recovery", "12"]))
    results = []
    runs = ([(PROTOTYPE, None)] if a.prototype_exe else []) + configs
    for name, extra in runs:
        log = os.path.join(a.out, name + ".console.txt"); trace = os.path.join(a.out, name + ".trace.csv")
        if name == PROTOTYPE:
            cmd = [os.path.abspath(a.prototype_exe), pcap]
        else:
            cmd = [exe, "--quiet", "--trace", trace] + extra + [pcap]
        print("running %-25s ..." % name, end=" ", flush=True)
        rc, wall, rss, err = measured_run(cmd, log)
        if name == PROTOTYPE:
            rows = nslib.prototype_console_to_rows(open(log).read())
            write_pseudo_trace(rows, trace, {"input": pcap, "window_sec": 5, "policy": PROTOTYPE})
        meta, trows = nslib.read_trace(trace)
        packets = int(meta.get("packets_read", 0)) if meta.get("packets_read") else None
        if packets is None:
            import re
            m = re.search(r"Packets read from PCAP:\s+(\d+)", open(log).read()); packets = int(m.group(1)) if m else None
        print("exit %d, %.2f s, %.1f MB peak" % (rc, wall, rss / 1e6))
        if err.strip(): open(os.path.join(a.out, name + ".stderr.txt"), "w").write(err)
        wl = os.path.join(a.out, name + ".windows.csv")
        lw = [sys.executable, os.path.join(HERE, "label_windows.py"), "--trace", trace, "--out", wl, "--mixed-share", str(a.mixed_share)]
        if a.flows:
            for f in a.flows: lw += ["--flows", f]
            lw += ["--offset", str(a.offset)]
            if a.ts_format: lw += ["--ts-format", a.ts_format]
            if a.hour12_heuristic: lw += ["--hour12-heuristic"]
        else:
            lw += ["--intervals", a.intervals]
        lr = subprocess.run(lw, capture_output=True, text=True)
        if lr.returncode != 0: print(lr.stdout, lr.stderr); sys.exit("label_windows failed for " + name)
        with open(wl, newline="") as fh:
            import csv
            labels = list(csv.DictReader(l for l in fh if not l.startswith("#")))
        res = evaluate.evaluate(trows, labels, float(meta.get("window_sec", 5)))
        res.update({"name": name, "command": " ".join(cmd), "exit_code": rc, "wall_s": round(wall, 3),
                    "peak_rss_mb": round(rss / 1e6, 2), "packets_read": packets,
                    "packets_per_s": round(packets / wall, 1) if packets and wall > 0 else None,
                    "mb_per_s": round(size / 1e6 / wall, 2) if wall > 0 else None,
                    "run_status": meta.get("run_status", "clean_eof" if rc == 0 else "exit_%d" % rc),
                    "label_summary": lr.stdout.strip()})
        results.append(res)
    env = ["date_utc=" + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "platform=" + platform.platform(),
           "machine=" + platform.machine(), "python=" + platform.python_version(),
           "exe=" + exe, "exe_sha256=" + sha256(exe), "libpcap_linkage=" + linkage(exe).replace("\n", " | "),
           "pcap=" + pcap, "pcap_bytes=%d" % size, "pcap_sha256=" + ("skipped (--no-hash)" if a.no_hash else sha256(pcap))]
    if a.prototype_exe: env += ["prototype_exe=" + os.path.abspath(a.prototype_exe), "prototype_exe_sha256=" + sha256(a.prototype_exe)]
    if a.flows: env += ["labels=" + ";".join(os.path.abspath(f) for f in a.flows), "offset_seconds=%s" % a.offset]
    else: env += ["labels=" + os.path.abspath(a.intervals)]
    if a.repo:
        g = subprocess.run(["git", "-C", a.repo, "describe", "--always", "--dirty", "--tags"], capture_output=True, text=True)
        h = subprocess.run(["git", "-C", a.repo, "rev-parse", "HEAD"], capture_output=True, text=True)
        env += ["git_describe=" + g.stdout.strip(), "git_head=" + h.stdout.strip()]
    open(os.path.join(a.out, "environment.txt"), "w").write("\n".join(env) + "\n")
    with open(os.path.join(a.out, "metrics.json"), "w") as fh: json.dump(results, fh, indent=2, default=list)
    L = ["# NetSentinel comparison: %s" % os.path.basename(pcap), "",
         "Generated by tools/eval/run_comparison.py. Every number below comes from the files in this directory.", "",
         "## Window-level metrics (primary: mixed windows excluded)", "",
         "| config | exit | usable windows | TP | FP | FN | TN | precision | recall | F1 | FPR | false alarms/h |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        m = r["primary"]
        L.append("| %s | %d | %d | %d | %d | %d | %d | %s | %s | %s | %s | %s |" % (r["name"], r["exit_code"], r["windows_usable"],
                 m["TP"], m["FP"], m["FN"], m["TN"], fmt(m["precision"]), fmt(m["recall"]), fmt(m["f1"]), fmt(m["fpr"]),
                 fmt(m["false_alarms_per_hour"], 2)))
    L += ["", "## Same, with mixed windows counted as attack", "",
          "| config | TP | FP | FN | TN | precision | recall | F1 | false alarms/h |", "|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        m = r["mixed_as_attack"]
        L.append("| %s | %d | %d | %d | %d | %s | %s | %s | %s |" % (r["name"], m["TP"], m["FP"], m["FN"], m["TN"],
                 fmt(m["precision"]), fmt(m["recall"]), fmt(m["f1"]), fmt(m["false_alarms_per_hour"], 2)))
    L += ["", "## Per attack type (events detected / events; window recall; median delay)", ""]
    types = sorted({t for r in results for t in r["per_attack_type"]})
    if types:
        L += ["| attack type | " + " | ".join(r["name"] for r in results) + " |", "|---|" + "---|" * len(results)]
        for t in types:
            cells = []
            for r in results:
                v = r["per_attack_type"].get(t)
                cells.append("—" if not v else "%d/%d; %s; %s" % (v["events_detected"], v["events"], fmt(v["window_recall"], 2),
                                                                  ("%.0f s" % v["median_delay_s"]) if v["median_delay_s"] is not None else "n/a"))
            L.append("| %s | %s |" % (t, " | ".join(cells)))
    L += ["", "## Exclusions (windows)", "", "| config | " + " | ".join(sorted({k for r in results for k in r["excluded"]})) + " |",
          "|---|" + "---|" * len({k for r in results for k in r["excluded"]})]
    keys = sorted({k for r in results for k in r["excluded"]})
    for r in results: L.append("| %s | %s |" % (r["name"], " | ".join(str(r["excluded"].get(k, 0)) for k in keys)))
    L += ["", "## Performance (this machine, this build)", "", "| config | wall s | packets | packets/s | MB/s | peak RSS MB | run status |",
          "|---|---|---|---|---|---|---|"]
    for r in results:
        L.append("| %s | %.2f | %s | %s | %s | %s | %s |" % (r["name"], r["wall_s"], r["packets_read"], r["packets_per_s"], r["mb_per_s"],
                 r["peak_rss_mb"], r["run_status"]))
    L += ["", "## Label summary", ""] + ["- %s: %s" % (r["name"], r["label_summary"].replace("\n", "; ")) for r in results]
    L += ["", "## Environment", "", "```"] + env + ["```", ""]
    open(os.path.join(a.out, "summary.md"), "w").write("\n".join(L))
    print("\n".join(L[:12 + len(results)]))
    print("\nwrote %s/summary.md, metrics.json, environment.txt" % a.out)

if __name__ == "__main__":
    main()
