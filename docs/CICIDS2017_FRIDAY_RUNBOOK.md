# CICIDS2017 Friday evaluation — macOS runbook

**What it produces:** the real-dataset (CICIDS2017 Friday) results reported for this project. Written for macOS;
the same commands work on Linux (use `ldd` instead of `otool -L`). Everything here was verified on Linux against a CICFlowMeter-format *stand-in* (not CICIDS2017 data);
the real Friday capture was run on macOS on 1 Nov 2026 with the evaluation version (commit `09d6269`; evidence:
`docs/evidence/friday_macos_2026-11-01/`). Do not report any number until steps 1–6 below have run
and the checks in step 7 pass.

Expected total time: about 15 minutes of commands plus download time and the runs. The runs read the
whole capture once per configuration (five configurations, six with the original-prototype row). Linux throughput on the
stand-in was about one million packets per second per configuration. On the evaluation Mac (arm64) each configuration
took about 7 s for the 9,997,874-packet Friday capture (`summary.md`, one run each).

---

## 0. Prerequisites (once)

```bash
xcode-select --install            # clang, make, git, python3 (skip if already installed)
brew install cmake wireshark      # cmake >= 3.14; wireshark provides capinfos, editcap, tshark
python3 --version                 # 3.8 or newer; the evaluation tools use only the standard library
```

libpcap: the plain CMake build below links the macOS system library (`/usr/lib/libpcap.A.dylib`; this is what the
evaluation build used, see `linkage.txt`). `scripts/verify_repository.sh` is stricter on macOS: it stops unless Homebrew
`pkg-config` and `libpcap` are installed (`brew install pkg-config libpcap`), and it points pkg-config at Homebrew's
libpcap, so a build made by that script can link Homebrew's library instead. The Catch2 test framework is downloaded by
CMake on the first configure, so the first build needs internet.

## 1. Build and test

```bash
cd netsentinel                                           # repository root
git describe --tags --dirty                              # record the exact version; must not end in -dirty
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cd build && ctest 2>&1 | tail -3 && cd ..                # expect: 100% tests passed, 51 tests (Linux and macOS)
otool -L build/netsentinel | grep -i pcap                # record which libpcap is linked
./build/netsentinel data/sample.pcap | tail -20          # one alert at window 25; final window partial
```

**Screenshot 1:** the `ctest` summary. **Screenshot 2:** the `otool -L` line. **Screenshot 3:** the sample run summary.

If any test fails on macOS, stop and keep the full `ctest --output-on-failure` output for diagnosis. Do not continue with
a failing build: the Linux results do not prove the Mac build.

## 2. Build the original-prototype reference binary (historical row, optional)

The original prototype (commit `f0e39c0`) is not part of the public snapshot; this step needs the development
repository. Skip it to run every configuration except the `original_prototype` row. In the development repository:

```bash
mkdir -p ../original-prototype && git archive f0e39c0 | tar -x -C ../original-prototype
cmake -S ../original-prototype -B ../original-prototype/build -DCMAKE_BUILD_TYPE=Release && cmake --build ../original-prototype/build -j
../original-prototype/build/netsentinel data/sample.pcap | tail -3   # original prototype: "Windows processed: 30", "Alerts raised: 1"
```

## 3. Get the data

1. **PCAP:** from the UNB CIC-IDS2017 page (https://www.unb.ca/cic/datasets/ids-2017.html), the Friday working-hours
   capture (`Friday-WorkingHours.pcap`). The site asks for a registration form, and its downloads only work in the
   browser session that registered (curl receives "Registration required."). Download `Friday-WorkingHours.md5` from
   the same folder and check `md5 -q Friday-WorkingHours.pcap` against it.
2. **Corrected labels:** from Engelen et al.'s page (https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html),
   the corrected CICIDS2017 flow CSV for **Friday** (`Friday-WorkingHours.csv` inside the 2021 `dataset.zip`; the
   2022 relabelling linked at the top of that page is a different version). Reference: G. Engelen, V. Rimmer, W. Joosen, "Troubleshooting an
   Intrusion Detection Dataset: the CICIDS2017 Case Study", WTMC 2021 workshop, 2021 IEEE Security and Privacy Workshops
   (SPW), https://doi.org/10.1109/SPW53761.2021.00009.
3. Check the CSV header: `head -1 friday.csv`. It must contain columns for timestamp, flow duration and label, and
   for the alignment step also source/destination IP and port and protocol. Column names are matched loosely
   (e.g. `Src IP` / `Source IP`, `Total Fwd Packet` / `Total Fwd Packets`). If the tool says a column is missing,
   compare the header with the patterns in `tools/eval/nslib.py`.
4. Check the format with `head -c 4 Friday-WorkingHours.pcap | od -An -tx1`. The UNB Friday file **is pcapng**
   (`0a 0d 0d 0a`) despite its `.pcap` name; convert it once and use the converted file for every configuration:
   `editcap -F pcap Friday-WorkingHours.pcap Friday-WorkingHours.classic.pcap` (expect `d4 c3 b2 a1`, 9,997,874 packets).
5. Expected offset: the corrected labels carry the clock of the machine that regenerated the flows (UTC+2), so
   `align.py` should measure about **−7200 s**. The often-quoted +3 h applies only to the original UNB CSVs.

## 4. Run everything with one command

```bash
tools/eval/run_friday.sh /path/to/Friday-WorkingHours.classic.pcap /path/to/Friday-WorkingHours.csv ../original-prototype/build/netsentinel results/friday
# optional 12-window recovery sensitivity row: prefix with WITH_SENSITIVITY=1
```

The script performs, in order, and logs everything to `results/friday/run_friday.log`:

| Step | What it does | Output file |
|---|---|---|
| integrity | SHA-256 and size of PCAP and CSV; first 4 bytes | `pcap.sha256`, `labels.sha256` |
| inspection | `capinfos`: link type, snaplen, packet count, first/last time, strict time order | `capinfos.txt` |
| — | label CSV header; `otool -L`; git describe | `labels_header.txt`, `linkage.txt`, `git_describe.txt` |
| alignment | measures the CSV-to-PCAP time offset from matching 5-tuples; **stops** if no dominant offset | `offset.json`, `align.txt` |
| comparison | runs the original prototype, the cumulative baseline, the gated baseline without and with the SD floor, and the frozen-threshold comparator; maps labels to windows; metrics; timing and memory | `summary.md`, `metrics.json`, `environment.txt`, per-run `*.trace.csv`, `*.windows.csv`, `*.console.txt` |

**Screenshot 4:** the terminal at the end of the run (the summary table). **Screenshot 5:** `results/friday/summary.md`
opened in a viewer. Take screenshots of the real terminal; do not recreate them.

## 5. If the alignment step stops

`align.py` refuses to give an offset unless one cluster of (PCAP time − label time) dominates. Read `align.txt`:

- **Two clusters about 12 h apart** (original UNB CSVs only; the corrected labels carry AM/PM and must not use
  `--hour12-heuristic`): the CSV prints afternoon times without AM/PM. Rerun by hand:
  `python3 tools/eval/align.py --pcap P --labels L --hour12-heuristic --out results/friday/offset.json`, then
  `python3 tools/eval/run_comparison.py --exe build/netsentinel --pcap P --flows L --offset <value> --hour12-heuristic --out results/friday --repo . --prototype-exe ../original-prototype/build/netsentinel`.
- **No matches:** the CSV does not belong to this PCAP, or its IP/port columns were not recognised. Inspect `align.txt`
  and `labels_header.txt`.
- **Timestamp format not recognised:** pass `--ts-format` (Python `strptime` syntax) to both tools.

## 6. Manual runs (if you do not want the script)

```bash
python3 tools/eval/align.py --pcap P --labels L --out results/friday/offset.json
python3 tools/eval/run_comparison.py --exe build/netsentinel --pcap P --flows L --offset <offset_seconds> \
    --out results/friday --repo . --prototype-exe ../original-prototype/build/netsentinel
```

## 7. Checks before any number is reported

1. `capinfos.txt`: link type is Ethernet (or Linux cooked); note the snaplen and whether "Strict time order" is True.
2. `cumulative.trace.csv` footer `packets_read` equals the capinfos packet count. Any difference must be explained.
3. `cumulative.trace.csv` footer: note `late_dropped`, `quarantined`, `gap_caps`, `skipped_ipv6`, `skipped_other_ethertype`,
   `skipped_malformed_ipv4`. Large values are findings to report, not errors to hide.
4. Every run's `run_status` is `clean_eof`. `read_error` means the PCAP is truncated; re-download.
5. `offset.json`: `accepted` is true; report the offset and the number of matched flows.
6. Label coverage (footer of `cumulative.windows.csv`): report labelled records total / overlapping / outside the capture,
   and the counts of attack, mixed, attempted, benign and unlabelled windows.
7. The original-prototype row (`original_prototype`; `r0_raw` in results produced before 3 Nov 2026) is a historical reference, distorted by the known defects; label it so in any table.

## 8. Files to keep for the report

`results/friday/summary.md`, `metrics.json`, `environment.txt`, `offset.json`, `align.txt`, `capinfos.txt`,
`linkage.txt`, `run_friday.log`, and the footers of `cumulative.windows.csv` and `cumulative.trace.csv`
(`grep '^#' results/friday/cumulative.windows.csv results/friday/cumulative.trace.csv`). The large trace files can be regenerated and need not be kept.

## 9. What these numbers can and cannot claim

They are window-level results for **one day** (Friday) of one dataset, with flow labels mapped to 5-second windows by
the rules in `docs/EVALUATION_METHODOLOGY.md`. They are not comparable with published flow-level machine-learning
results. Parameters (5 s, warm-up 20, threshold 3.0, SD floors, recovery 60) were fixed before this run and were not
tuned on Friday data.
