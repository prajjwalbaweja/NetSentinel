#!/usr/bin/env python3
"""Mutation check for the characterization suite.  usage: run_mutants.py [--catch2-src DIR] [--only M01,M02] [--jobs N]
Copies the repo (without .git / build dirs) into a TEMP dir, builds once, verifies the pristine copy passes ctest, then for each mutant:
applies exact string replacement(s) to the TEMP copy, rebuilds, runs ctest, restores the file.  The repo itself is never modified.
Each mutant carries a PREDICTION written before the run: kill | survive-equivalent | survive-gap (a missing fixture, not a missing test).
Outcome: KILLED (>=1 test failed), SURVIVED (all tests passed), BUILD-FAIL (invalid mutant), SPEC-ERROR (old string not found exactly once)."""
import sys, os, shutil, subprocess, tempfile, argparse, re
ap = argparse.ArgumentParser(); ap.add_argument("--catch2-src"); ap.add_argument("--only"); ap.add_argument("--jobs", default="4"); a = ap.parse_args()
repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
M = []  # (id, description, prediction, [(file, old, new), ...])
def m(i, d, p, *edits): M.append((i, d, p, list(edits)))
m("M01", "z threshold 3.0 -> 2.9", "kill", ("include/IAnomalyScorer.hpp", "DEFAULT_Z_THRESHOLD = 3.0", "DEFAULT_Z_THRESHOLD = 2.9"))
m("M02", "z threshold 3.0 -> 3.1", "kill", ("include/IAnomalyScorer.hpp", "DEFAULT_Z_THRESHOLD = 3.0", "DEFAULT_Z_THRESHOLD = 3.1"))
m("M03", "z threshold 3.0 -> 2.0", "kill", ("include/IAnomalyScorer.hpp", "DEFAULT_Z_THRESHOLD = 3.0", "DEFAULT_Z_THRESHOLD = 2.0"))
m("M04", "warm-up 20 -> 19", "kill", ("include/IStatEngine.hpp", "WARMUP_WINDOW_COUNT = 20", "WARMUP_WINDOW_COUNT = 19"))
m("M05", "warm-up 20 -> 21", "kill", ("include/IStatEngine.hpp", "WARMUP_WINDOW_COUNT = 20", "WARMUP_WINDOW_COUNT = 21"))
m("M06", "window length 5.0 -> 4.0", "kill", ("include/IWindowAggregator.hpp", "WINDOW_LENGTH_SEC = 5.0", "WINDOW_LENGTH_SEC = 4.0"))
m("M07", "variance epsilon 1e-6 -> 1e-5", "survive-gap", ("include/IStatEngine.hpp", "VARIANCE_EPSILON = 1e-6", "VARIANCE_EPSILON = 1e-5"))
m("M08", "variance epsilon 1e-6 -> 0.3", "kill", ("include/IStatEngine.hpp", "VARIANCE_EPSILON = 1e-6", "VARIANCE_EPSILON = 0.3"))
m("M09", "population variance (n instead of n-1)", "kill", ("src/StatEngine.cpp", "m2_ / static_cast<double>(count_ - 1)", "m2_ / static_cast<double>(count_)"))
m("M10", "Welford delta2 = delta (classic bug)", "kill", ("src/StatEngine.cpp", "const double delta2 = value - mean_;", "const double delta2 = delta;"))
m("M11", "ignore negative z (|z| -> z)", "kill", ("src/AnomalyScorer.cpp", "std::fabs(z) > DEFAULT_Z_THRESHOLD", "z > DEFAULT_Z_THRESHOLD"))
m("M12", "threshold test > -> >=", "survive-equivalent", ("src/AnomalyScorer.cpp", "std::fabs(z) > DEFAULT_Z_THRESHOLD", "std::fabs(z) >= DEFAULT_Z_THRESHOLD"))
m("M13", "scorer drops its isWarmedUp() check (zScore returns NaN anyway)", "survive-equivalent", ("src/AnomalyScorer.cpp", "fb.baseline == nullptr || !fb.baseline->isWarmedUp()", "fb.baseline == nullptr"))
m("M14", "window close test >= -> >", "kill", ("src/WindowAggregator.cpp", "latestTimestampSec >= windowEnd_", "latestTimestampSec > windowEnd_"))
m("M15", "count dst port for every protocol", "survive-gap", ("src/WindowAggregator.cpp", "if (packet.protocol == PROTO_TCP || packet.protocol == PROTO_UDP) {", "if (true) {"))
m("M16", "UDP port parsing disabled", "survive-gap", ("src/FeatureExtractor.cpp", "else if (feature.protocol == PROTO_UDP &&", "else if (false &&"))
m("M17", "ethertype IPv4 check removed", "survive-gap", ("src/FeatureExtractor.cpp", "if (ethertype != ETHERTYPE_IPV4) {", "if (false) {"))
m("M18", "update baselines BEFORE scoring", "kill",
  ("src/main.cpp", "    engines.packetCount.update(static_cast<double>(w.packet_count));\n    engines.avgPacketSize.update(w.avg_packet_size_bytes);\n    engines.uniqueDstPorts.update(static_cast<double>(w.unique_dst_ports));\n    engines.uniqueDstIps.update(static_cast<double>(w.unique_dst_ips));\n", ""),
  ("src/main.cpp", "    printZScores(baselines);\n", "    engines.packetCount.update(static_cast<double>(w.packet_count));\n    engines.avgPacketSize.update(w.avg_packet_size_bytes);\n    engines.uniqueDstPorts.update(static_cast<double>(w.unique_dst_ports));\n    engines.uniqueDstIps.update(static_cast<double>(w.unique_dst_ips));\n    printZScores(baselines);\n"))
m("M19", "final partial window never closed", "kill", ("src/main.cpp", "if (aggregator.hasPendingPacket()) {", "if (false) {"))
m("M20", "skipped-packet counter removed", "kill", ("src/main.cpp", "++packetsSkipped;", ""))
m("M21", "alert lists only the first triggered feature", "kill", ("src/AnomalyScorer.cpp", "event.triggered_features = std::move(triggered);", "triggered.resize(1); event.triggered_features = std::move(triggered);"))
m("M22", "dst IP read from src IP offset", "kill", ("src/FeatureExtractor.cpp", "ipv4ToString(packet.data + ipOffset + 16)", "ipv4ToString(packet.data + ipOffset + 12)"))
m("M23", "dst port read from src port offset (TCP)", "kill", ("src/FeatureExtractor.cpp", "feature.src_port = readU16BE(packet.data + transportOffset);\n        feature.dst_port = readU16BE(packet.data + transportOffset + 2);\n    } else if", "feature.src_port = readU16BE(packet.data + transportOffset);\n        feature.dst_port = readU16BE(packet.data + transportOffset);\n    } else if"))
m("M24", "packet size off by Ethernet header (length-14)", "kill", ("src/FeatureExtractor.cpp", "static_cast<uint32_t>(packet.length)", "static_cast<uint32_t>(packet.length - 14)"))
m("M25", "captured length -> original length", "survive-gap", ("src/PcapFileCapture.cpp", "view.length = header->caplen;", "view.length = header->len;"))
m("M26", "read error never recorded", "kill", ("src/PcapFileCapture.cpp", "            readError_ = true;", "            readError_ = false;"))
m("M27", "clean EOF also flagged as a read error", "kill", ("src/PcapFileCapture.cpp", "if (result == -1) {", "if (result == -1 || result == -2) {"))
m("M28", "read-error exit code 2 -> 1", "kill", ("src/main.cpp", "        return 2;", "        return 1;"))
sel = set(a.only.split(",")) if a.only else None
work = tempfile.mkdtemp(prefix="ns_mut_"); src = os.path.join(work, "repo"); bld = os.path.join(work, "build")
shutil.copytree(repo, src, ignore=shutil.ignore_patterns(".git", "build*", "__pycache__", "*.gcda", "*.gcno"))
def run(cmd, **kw): return subprocess.run(cmd, capture_output=True, text=True, **kw)
cfg = ["cmake", "-S", src, "-B", bld] + (["-DFETCHCONTENT_SOURCE_DIR_CATCH2=" + a.catch2_src] if a.catch2_src else [])
assert run(cfg).returncode == 0, "configure failed"; assert run(["cmake", "--build", bld, "-j", a.jobs]).returncode == 0, "pristine build failed"
def ctest():
    r = run(["ctest", "--output-on-failure"], cwd=bld); failed = re.findall(r"^\s*\d+/\d+ Test\s+#\d+: (\S+) \.+\*\*\*(?:Failed|Exception|Not Run|Timeout)", r.stdout, re.M)
    if not failed: failed = re.findall(r"^\s+\d+ - (\S+) \(", r.stdout, re.M) if r.returncode else []
    return r.returncode, failed
rc, f = ctest(); print("pristine copy: ctest rc=%d failed=%s" % (rc, f)); assert rc == 0, "pristine copy must pass before mutating"
print("%-4s %-9s %-18s %-60s %s" % ("id", "predicted", "outcome", "mutation", "failing tests"))
res = []
for i, d, pred, edits in M:
    if sel and i not in sel: continue
    saved = {}; spec_err = False
    for fpath, old, new in edits:
        p = os.path.join(src, fpath); t = open(p).read(); saved.setdefault(fpath, t)
        if t.count(old) != 1: spec_err = True; break
        open(p, "w").write(t.replace(old, new, 1))
    if spec_err: out, failed = "SPEC-ERROR", []
    elif run(["cmake", "--build", bld, "-j", a.jobs]).returncode != 0: out, failed = "BUILD-FAIL", []
    else:
        rc, failed = ctest(); out = "SURVIVED" if rc == 0 else "KILLED"
    for fpath, t in saved.items(): open(os.path.join(src, fpath), "w").write(t)
    res.append((i, pred, out)); print("%-4s %-9s %-18s %-60s %s" % (i, pred, out, d[:60], ",".join(failed[:4]) + ("..." if len(failed) > 4 else "")), flush=True)
run(["cmake", "--build", bld, "-j", a.jobs])
k = sum(1 for _, _, o in res if o == "KILLED"); s = [(i, p) for i, p, o in res if o == "SURVIVED"]
mism = [(i, p, o) for i, p, o in res if (p == "kill") != (o == "KILLED")]
print("\nSUMMARY: %d mutants, %d killed, %d survived, %d invalid" % (len(res), k, len(s), sum(1 for _, _, o in res if o in ("BUILD-FAIL", "SPEC-ERROR"))))
print("survivors (id, predicted):", s); print("prediction mismatches (id, predicted, actual):", mism or "none")
shutil.rmtree(work, ignore_errors=True)
sys.exit(0)
