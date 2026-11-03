# Evaluation methodology

This document fixes the evaluation rules **before** any CICIDS2017 result exists. Changing a rule after
seeing results must be recorded here with the reason.

## 1. Unit of evaluation

NetSentinel decides per **5-second window**. Every metric is therefore window-level or event-level, never flow-level.
Results are not comparable with flow-classification papers on CICIDS2017.

## 2. Detector configurations compared

| Name | Name in results produced before 3 Nov 2026 | Meaning | Command-line options |
|---|---|---|---|
| `original_prototype` | `r0_raw` | unmodified original prototype (commit `f0e39c0`), historical reference; still has the defects listed in `docs/CHANGES.md` | separate binary |
| `cumulative` | `b0` | original cumulative Welford baseline, every scored window learned, original variance rule; runs inside the corrected pipeline | `--policy cumulative` |
| `gated` | `b1_nofloor` | gated cumulative baseline: alerting windows are not learned; after 60 consecutive gated alerting windows, learning resumes | `--policy gated` |
| `gated_sd_floor` | `b1_floor` | as `gated`, plus σ_eff,i = max(σ_i, ε_i), ε = (0.5 packets, 2.0 bytes, 0.5 ports, 0.5 IPs) | `--policy gated --sd-floor` |
| `frozen` | `frozen` | fixed-threshold comparator: thresholds = mean ± 3σ from the 20 warm-up windows, frozen for the rest of the run | `--policy frozen` |
| `gated_sd_floor_recovery12` | `b1_floor_r12` | sensitivity row: recovery after 12 instead of 60 windows (optional) | `--policy gated --sd-floor --recovery 12` |

The four rows `original_prototype` → `cumulative` → `gated` → `gated_sd_floor` separate three effects: processing
corrections (`original_prototype` vs `cumulative`), gating (`cumulative` vs `gated`) and the SD floor (`gated` vs
`gated_sd_floor`). The saved evidence in `docs/evidence/` keeps the older names exactly as the tools wrote them; only
the names changed, not the configurations (`b0`/`b1` remain accepted by `--policy` as aliases).

Common to all: window 5 s, warm-up 20 windows, threshold absolute z > 3.0, gap cap 60 s. None of these was tuned on
CICIDS2017. The SD floors were chosen on synthetic scenarios only (`docs/evidence/floor_sweep/floor_sweep.md`).

### Gated-baseline recovery rule, exactly

A scored window that raises an alert increments a counter. While the counter is ≤ 60, the window is **gated** (not
learned). The 61st and later consecutive alerting windows are learned (`forced_update`). A scored window without an
alert resets the counter to 0 and is learned. Idle, no-parsed-traffic and partial windows are never learned and do not
change the counter. Risk (tested in `tests/unit/test_policy.cpp` and synthetic scenario `s2_sustained`): an attack that
lasts longer than 60 windows (5 minutes) starts to be absorbed after the 60th window.

## 3. Mapping flow labels to windows (CICIDS2017)

Corrected labels (Engelen, Rimmer and Joosen, WTMC 2021 workshop, published in the 2021 IEEE Security and Privacy
Workshops (SPW), https://doi.org/10.1109/SPW53761.2021.00009) are per-flow records produced by a fixed CICFlowMeter from the original
PCAPs. Rules, implemented in `tools/eval/label_windows.py`:

1. **Time alignment.** Label timestamps are naive wall-clock times. The offset to PCAP epoch time is *measured* by
   `tools/eval/align.py`: the first PCAP packet of each labelled 5-tuple is matched, and the dominant cluster of
   (PCAP time − label time) gives the offset (median). Accuracy is limited by label timestamp resolution (1 s on the
   Linux stand-in: 10800.49 s recovered for a true 10800 s). The tool refuses an offset without a dominant cluster.
2. **Flow interval.** A flow occupies [start + offset, start + offset + duration]; zero-duration flows are points.
3. **Per window,** overlapping flows are counted as attack (label not BENIGN, not "… - Attempted"), attempted, or benign.
4. **Attack share.** Each flow's forward + backward packets are spread uniformly over its duration; the overlapping
   fraction is attributed to the window. attack share = attack packets ÷ all labelled packets in the window.
5. **Window label.**
   - `attack`: at least one attack flow and attack share ≥ 10 %
   - `mixed`: at least one attack flow but attack share < 10 %
   - `attempted`: only attempted (and benign) flows
   - `benign`: only benign flows
   - `unlabelled`: no labelled flow overlaps the window
6. **Attack types** of a window: all attack types overlapping it.

Known weaknesses of this mapping: CICFlowMeter's flow timeout splits long connections, so a flow's packets are not
really uniform over its duration; the 10 % mixed threshold is a convention, so results are reported both without and
with mixed windows; packets that match no flow (ARP, IPv6 and others) do not change a window's label.

## 4. Exclusions (reported with counts in every summary)

- Windows not scored by the detector: idle, no parsed traffic, partial final window.
- Warm-up windows (first 20 scored windows).
- Windows labelled `unlabelled` or `attempted` (Engelen et al.'s own benchmark relabels attempted flows as benign;
  here they are kept separate and excluded).
- `mixed` windows: excluded from the primary metrics, counted as attack in the second variant.

## 5. Metrics

- **Window level:** TP (alert & attack), FP (alert & benign), FN, TN; precision, recall, F1, false-positive rate;
  **false alarms per hour** = FP ÷ (benign windows × 5 s ÷ 3600).
- **Event level:** an attack event is a maximal run of consecutive attack-or-mixed windows. It is detected if any of its
  scored windows alerts. **Detection delay** = start of the first alerting window − event start (a multiple of 5 s).
- **Per attack type:** events detected / events, window recall, median delay, and how often each feature triggered.
- **Performance:** wall time, packets per second, MB per second, peak resident memory of the detector process
  (`wait4` resource usage), with machine, OS, build type and libpcap linkage recorded in `environment.txt`.

## 6. Synthetic scenarios (supplement)

`tools/eval/make_scenarios.py` defines six labelled scenarios that each test one behaviour (step attack, sustained
flood, slow ramp, legitimate permanent shift, idle gap, quiet host with a scan). They show the policies' trade-offs
under controlled conditions; they do not measure real-world accuracy. Linux results: `docs/evidence/synthetic_scenarios_linux.md`.

## 7. What is not claimed

No novelty; no generalisation beyond Friday of CICIDS2017; no tuned parameters; no comparison with flow-level
classifiers; synthetic scenarios are not evidence of real-world accuracy.

**Status note (added 1 Nov 2026, after the run; no rule in sections 1–6 was changed).** The Friday evaluation was run
once, on macOS, with the evaluation version (commit `09d6269`); results in `docs/evidence/friday_macos_2026-11-01/`. Later
commits changed only comments, message strings, documentation and screenshots; the evaluation was not re-run on them.
It has not been run on Linux.
