#!/usr/bin/env bash
# One-command CICIDS2017 Friday evaluation (macOS or Linux). Runs the steps of docs/CICIDS2017_FRIDAY_RUNBOOK.md and keeps every log.
# usage: tools/eval/run_friday.sh FRIDAY.pcap LABELS.csv [PROTOTYPE_EXE] [OUT_DIR]
#   FRIDAY.pcap  the UNB Friday-WorkingHours capture (classic pcap; convert pcapng with editcap -F pcap)
#   LABELS.csv   the corrected (Engelen et al., WTMC 2021) Friday flow CSV
#   PROTOTYPE_EXE optional: path to the original prototype binary (commit f0e39c0) for the historical row
#   OUT_DIR      default results/friday
# Run from the repository root after building build/netsentinel (Release).
set -u
PCAP="${1:?usage: run_friday.sh FRIDAY.pcap LABELS.csv [PROTOTYPE_EXE] [OUT_DIR]}"
LABELS="${2:?usage: run_friday.sh FRIDAY.pcap LABELS.csv [PROTOTYPE_EXE] [OUT_DIR]}"
PROTOTYPE_EXE="${3:-}"
OUT="${4:-results/friday}"
EXE="build/netsentinel"
mkdir -p "$OUT"
LOG="$OUT/run_friday.log"
say() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }
hash256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi; }

[ -x "$EXE" ] || { say "ERROR: $EXE not found. Build first: cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j"; exit 1; }
say "step 2: integrity"
hash256 "$PCAP" | tee "$OUT/pcap.sha256" | tee -a "$LOG"
hash256 "$LABELS" | tee "$OUT/labels.sha256" | tee -a "$LOG"
ls -l "$PCAP" "$LABELS" | tee -a "$LOG"
head -c 4 "$PCAP" | od -An -tx1 | tee -a "$LOG"   # a1b2c3d4 / d4c3b2a1 = classic pcap; 0a0d0d0a = pcapng (convert first)

say "step 3: capture inspection (capinfos)"
if command -v capinfos >/dev/null; then
  capinfos -T -m -a -e -c -l -E -o -s "$PCAP" | tee "$OUT/capinfos.txt" | tee -a "$LOG"
else
  say "WARNING: capinfos not found (install Wireshark CLI tools). Step 3 must be done by hand." | tee "$OUT/capinfos.txt"
fi
say "step 3b: label CSV header"
head -1 "$LABELS" | tee "$OUT/labels_header.txt" | tee -a "$LOG"

say "build linkage (which libpcap is linked)"
if command -v otool >/dev/null; then otool -L "$EXE" | tee "$OUT/linkage.txt"; else ldd "$EXE" | tee "$OUT/linkage.txt"; fi
git describe --always --tags --dirty 2>/dev/null | tee "$OUT/git_describe.txt" | tee -a "$LOG"

say "step 5: timestamp alignment"
python3 tools/eval/align.py --pcap "$PCAP" --labels "$LABELS" --out "$OUT/offset.json" 2>&1 | tee "$OUT/align.txt" | tee -a "$LOG"
ALIGN_RC=${PIPESTATUS[0]}
if [ "$ALIGN_RC" -ne 0 ]; then
  say "STOP: offset not accepted (exit $ALIGN_RC). Read $OUT/align.txt. If two clusters 12 h apart appear, rerun align.py with --hour12-heuristic and pass the same flag to run_comparison.py."
  exit 3
fi
OFFSET=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['offset_seconds'])" "$OUT/offset.json")
say "offset accepted: $OFFSET s"

say "steps 4, 6-12: comparison runs (this reads the whole capture once per configuration)"
ARGS=(--exe "$EXE" --pcap "$PCAP" --flows "$LABELS" --offset "$OFFSET" --out "$OUT" --repo .)
[ -n "$PROTOTYPE_EXE" ] && ARGS+=(--prototype-exe "$PROTOTYPE_EXE")
[ "${WITH_SENSITIVITY:-0}" = "1" ] && ARGS+=(--with-sensitivity)
python3 tools/eval/run_comparison.py "${ARGS[@]}" 2>&1 | tee -a "$LOG"
RC=${PIPESTATUS[0]}
[ "$RC" -eq 0 ] || { say "ERROR: run_comparison.py failed (exit $RC)"; exit "$RC"; }

say "step 4 check: packets read must equal the capinfos packet count"
grep -i "Number of packets" "$OUT/capinfos.txt" 2>/dev/null | tee -a "$LOG"
grep -h "^# packets_read=" "$OUT"/cumulative.trace.csv | tee -a "$LOG"
say "done. Key outputs: $OUT/summary.md metrics.json environment.txt offset.json align.txt capinfos.txt linkage.txt run_friday.log"
