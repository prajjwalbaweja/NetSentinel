# What changed from the original prototype, and how it was verified

Development started from the original prototype, commit `f0e39c0`, which is kept unchanged as the reference for
every comparison. All commit hashes in this document refer to the development repository, which keeps the full
history; this public repository is a single snapshot of the final version. Defect and test verification below was run on Linux (Ubuntu
container, GCC, system libpcap).

**macOS verification (1 Nov 2026, macOS 26.7.1 arm64, evaluation version, commit `09d6269`):** clean Release build, `ctest` 51/51,
`otool -L` shows the system `/usr/lib/libpcap.A.dylib`, `sample.pcap` 30 windows / 1 alert, and the CICIDS2017 Friday
evaluation (evidence: `docs/evidence/friday_macos_2026-11-01/`). The ASan + UBSan + strict-warnings build has not been run
on macOS.

**Evaluation provenance.** The CICIDS2017 Friday results come from the evaluation version, commit `09d6269`. The
later commits listed below, up to the final project version, changed only comments, two command-line message strings (the `--sd-floor`
help line and its misuse message), documentation and screenshots. No change to detection logic was identified
(`git diff 09d6269 -- src include` in the development repository), but the Friday evaluation has **not** been re-run on the final binary.

Commit messages, tags and older evidence files use short development labels (for example "NS-08" or "E5"). The
**Legacy label** column below and `docs/GLOSSARY.md` map each one to the description used here.

## Development history (development-repository commits)

| Commit | Content |
|---|---|
| `04e7d78` | Capture object made non-copyable; it closes its handle on reopen |
| `7a93969` | Parser fixes: VLAN / QinQ / Linux SLL, link-type check, on-wire length, fragments, 4-byte port rule, skip reasons |
| `26e1545` | `Pipeline` class: time policy, idle and partial windows, audit fixtures, oracle update; default sample path fixed |
| `ec04fe9` | Exactly sized test buffers; 8/8 parser mutants killed under ASan. End of the correctness fixes |
| `c87d01a` | Per-window CSV trace and command-line options. End of the instrumentation work |
| `0619d8a` | Baseline comparison: gated baseline, SD floor, frozen-threshold comparator |
| `a81a181` | Evaluation pipeline, synthetic scenarios, configuration comparison runner, performance measurement |
| `23dc762` | Documentation and runbook; first fully verified Linux build |
| later commits up to `09d6269` (evaluation version) | Corrections of 1 Nov: tests for the variance-epsilon and captured-length mutants, audit fixture hashes, status corrections |
| later commits | CICIDS2017 Friday evidence; documentation corrections; glossary; plain-language terminology in comments, tests and documents |
| `fc8e249` | Screenshots of the macOS build, tests and evaluation; no code change |
| `a70d215` | Documentation corrections: evaluation provenance, platform of each result, slow-ramp limitation, citation, runbook command. Version submitted for college evaluation |
| later commits (final project version, tag `v1.0.0`) | Plain names for policies and result rows, privacy redaction of evidence paths, public README, descriptive version names |

The commit message of `ec04fe9` says "8/8 parser mutants killed". That is true for the eight parser mutants in
`docs/evidence/parser_mutants.txt`, but it does not show that the test suite can detect every broken detector
(see the last row of the defect table).

## Defects in the original prototype and their status (Linux)

| Defect | Original behaviour (re-run 31 Oct) | Current behaviour | Closing test | Legacy label |
|---|---|---|---|---|
| Constant feature never alerts | zero variance → z inconclusive | **Cumulative baseline unchanged by design**; the gated baseline with the SD floor detects it | `audit_constant_then_scan_tail`, `audit_constant_then_scan_tail_gated_sd_floor`, unit `[sd-floor]` | NS-01 |
| Far-future timestamp | one packet created 736 windows and a 301-packet window | packet quarantined, 0 alerts | `audit_future_ts_glitch`, `oracle_audit_future_ts_glitch`, unit `[time-policy]` | NS-02 |
| Epoch-0 first packet | run effectively hangs | 1 gap cap, 12 idle windows, finishes in about 0.01 s | `audit_epoch_zero_first`, unit `[time-policy]` | NS-03 |
| Read error reported as clean end of file | (fixed in the original prototype) | unchanged: exit 2 on read error; trace `run_status=read_error` | `golden_trunc_*`, `audit_truncated_file`, `cli_and_trace` | NS-04 |
| Partial final window scored | false alert | partial window neither scored nor learned | `audit_no_attack_with_tail`, unit `[partial-window]` | NS-05 |
| Idle windows learned as zeros | IPv6 scan reported as a drop | idle / no-parsed windows neither scored nor learned; IPv6 counted as skipped | `audit_gap_10min`, `audit_ipv6_attack`, unit `[idle-window]` | NS-06 |
| VLAN / Linux SLL not parsed | 0 parsed, exit 0 | 600/600 parsed; unsupported link types exit 1 with a message | `audit_vlan_tagged`, `audit_linux_sll`, `audit_unsupported_linktype`, unit `[link-layers]` | NS-07 |
| Average size from captured length | avg size = snaplen (64) | on-wire length (1514); bounds still use the captured length | `audit_snaplen64`, unit `[on-wire-length]`, `[captured-length]` | NS-08 |
| Fragment payload read as ports | up to 40 "ports" per window in the audit fixture | no ports from non-first fragments | `audit_fragments`, unit `[fragments]` | NS-09 |
| Truncated TCP header | counted as port 0 | port read when 4 transport bytes exist; otherwise none | `audit_tcp_truncated_hdr`, unit `[truncated-transport]` | NS-10 |
| Capture copy / reopen | copy → use-after-free; reopen leaks | copy does not compile; reopen closes (ASan/LSan clean) | unit `[capture-ownership]` under ASan | NS-11 |
| Hard-coded sample path | default path on the author's machine | default `data/sample.pcap` next to the script | `fixtures_regenerate` | NS-12 |
| Test suite could not detect a broken detector or parser | — | **Partially closed.** Eight parser mutants are killed (`docs/evidence/parser_mutants.txt`). The mutation harness (`tests/mutation/run_mutants.py`) run on commit `23dc762` on 1 Nov: 28 mutants, 16 killed, 2 survived (M07 variance epsilon 1e-6 → 1e-5; M25 view length = on-wire length), 10 invalid (their target code no longer exists). M07 and M25 now have dedicated tests (`[variance-epsilon]`, `[captured-length]`); re-run after adding them: **28 mutants, 18 killed, 0 survived, 10 invalid**. The harness has not been extended to the new gated-baseline, SD-floor, time-policy and trace code, so this is not fully closed | unit `[exact-buffers]`, `[variance-epsilon]`, `[captured-length]` | NS-13 |
| Fractional timestamps and epsilon boundary untested | — | fractional-timestamp unit test; variance-boundary tests bracket 1e-6 (StatEngine unchanged) | unit `[fractional-time]`, `[variance-epsilon]` | RF-02 |
| Oracle on 4 clean fixtures only | — | oracle cross-checks 13 audit fixtures too | `oracle_audit_*` | RF-03 |
| Read error visible only on stderr | — | trace footer `run_status` | `cli_and_trace` | RF-05 |

Not fixed (documented limitations of the method): false-alarm rate depends on traffic shape; slow change is detected only
partly (synthetic scenario `s3_slow_ramp`, Linux: the cumulative baseline flagged 33 % and the gated baseline 81 % of the
ramp windows); the cumulative baseline's sensitivity changes with uptime; IPv6 is not analysed;
the one-packet look-ahead cannot distinguish two consecutive far-future packets from a real jump.

## Requirement status

| Requirement | Status | Detail | Legacy label |
|---|---|---|---|
| Per-window trace | Implemented and Linux-tested | `--trace`, format `netsentinel-trace-v1` | E1 |
| Evaluation tools | Implemented; executed on synthetic scenarios, a stand-in, and CICIDS2017 Friday on macOS (1 Nov 2026) | Results: `docs/evidence/friday_macos_2026-11-01/summary.md` | E2 |
| Time and window policy | Implemented and Linux-tested | late-packet drop, far-future quarantine, idle-gap cap; idle and partial windows not scored or learned | E3 |
| Parser fixes | Implemented and Linux-tested | link layers, on-wire length, fragments, truncated headers | E4 |
| **Command-line options** | **Partially completed** | Implemented: `--threshold`, `--gap-cap`, `--policy`, `--recovery`, `--sd-floor`, `--floor-values`, `--trace`, `--quiet`. Not implemented: configurable window length and warm-up; the window stays 5 s (`IWindowAggregator::WINDOW_LENGTH_SEC`) and the warm-up 20 windows (`IStatEngine::WARMUP_WINDOW_COUNT`). The original requirement for a configurable window size is therefore only partly met | E5 |
| Performance measurement | Implemented; measured on CICIDS2017 Friday on macOS, one run per configuration | 1.30–1.50 M packets/s, peak memory under 2 MB; repeated and cold-cache runs not measured | E6 |
| Capture-handle ownership | Implemented and Linux-tested | see the capture copy / reopen defect | E7 |

## Integrity manifests

- **Root `MANIFEST.sha256` is the historical manifest** of the audited original tree (29 files, created in commit
  `81d7b83`). It is deliberately left unchanged as a provenance record. Because the current version modifies many of those
  files, `sha256sum -c MANIFEST.sha256` reports FAILED entries (5 at `f0e39c0`, 16 at `23dc762`, 17 at
  `09d6269`, 25 after the terminology cleanup of comments); this is expected, not corruption. Its only automated
  use is the `data/sample.pcap` entry, which still matches (`fixtures_verify`).
- **`tests/data/MANIFEST.sha256`** covers every test fixture: the 9 original synthetic fixtures and, since 1 Nov, the 15
  audit fixtures in `tests/data/audit/`. CTest `fixtures_verify` checks all 24 entries plus `data/sample.pcap` on every run.

## Verification commands (Linux, as run)

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j && (cd build && ctest)
cmake -S . -B build_asan -DNS_SANITIZE=ON -DNS_STRICT_WARNINGS=ON && cmake --build build_asan -j
(cd build_asan && ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ctest)
bash scripts/verify_repository.sh
python3 tools/experiments/floor_sweep.py --exe build/netsentinel --out docs/evidence/floor_sweep
python3 tools/eval/run_synthetic_suite.py --exe build/netsentinel --prototype-exe <original prototype build>/netsentinel --out results/synthetic
```

The exact results of earlier verification runs are in `docs/evidence/verification_linux_23dc762.txt` (commit `23dc762`)
and `docs/evidence/verification_linux_09d6269.txt` (the evaluation version, commit `09d6269`). Those files record the commands as
run at the time, including the script's earlier name `scripts/phase0_verify.sh`.

## Design notes

- **Pipeline** (`include/Pipeline.hpp`) holds the per-packet logic that used to be in `main.cpp`, so the time and window
  policy is unit-tested with synthetic timestamps. `main.cpp` reads packets, parses options and prints.
- **Time policy:** late = earlier than the open window's start → dropped and counted; out-of-order inside the open
  window → processed; > 60 s ahead of the latest accepted timestamp → held one packet, quarantined if the next packet
  is back on the old timeline (also at end of file); idle gaps emit at most 12 empty windows, then the grid jumps.
- **Idle and partial windows:** idle, no-parsed-traffic and partial windows appear in the console and trace but are never
  scored or learned.
- **The cumulative baseline (`--policy cumulative`) is byte-for-byte the original policy** (`StatEngine` untouched): Welford
  update, sample variance, epsilon 1e-6 → inconclusive z.
- **SD floor** is applied in the scorer (`AnomalyScorer::effectiveZ`) only when `FeatureBaseline::sd_floor > 0`, which
  the pipeline sets only for `--policy gated --sd-floor`; the command line rejects `--sd-floor` with other policies.
- **Trace format** `netsentinel-trace-v1`: one CSV row per window, `#` header (configuration) and footer (run status
  and counters); see `include/TraceWriter.hpp`.

## Terminology change (3 Nov 2026)

The command line, code, result names and documentation now use `cumulative`, `gated` and `frozen` instead of the
internal labels `b0` and `b1`; `--policy b0` and `--policy b1` remain accepted as aliases. Evaluation rows are now
`original_prototype`, `cumulative`, `gated`, `gated_sd_floor`, `frozen` and `gated_sd_floor_recovery12` (previously
`r0_raw`, `b0`, `b1_nofloor`, `b1_floor`, `frozen`, `b1_floor_r12`). Detection logic, thresholds and methodology are
unchanged. Check: every capture in `data/` and `tests/data/` (25 files) was run under six configurations with the
binary before and after the change; all console output, error output, exit codes and traces were identical except
for the policy name. `ctest` 51/51 in Release and ASan + UBSan builds (Linux). Files in `docs/evidence/` keep the old
labels as produced.

