# Glossary — terms and development labels

Documents, code, command-line values and result names use plain terms (cumulative baseline, gated baseline,
SD floor, …). Short labels still appear in places that should not be rewritten: git commit messages and tags, and the
evidence files produced before 3 Nov 2026 (for example `b1_floor` rows in `docs/evidence/friday_macos_2026-11-01/`).
The old command-line values `b0` and `b1` are still accepted as aliases. This page maps every label to its meaning so
that history stays traceable.

## Versions (development labels, historical)

Plain names: original prototype = `f0e39c0`; evaluation version = `09d6269`; final project version = tag `v1.0.0`.
All commit hashes and the tag names below belong to the development repository, which keeps the full history; the
public repository is a single snapshot of the final version.

| Label | Meaning |
|---|---|
| **R0** | The original prototype after its source audit: commit `f0e39c0`, tag `r0-reference`. Kept unchanged as the reference for every comparison. |
| **R0-0 … R0-4** | The small verification tasks done on R0 before any upgrade (manifest and provenance, fixture checks, characterization tests, build options, read-error exit code). |
| **R1** (release) | The upgraded release line, development branch `r1-upgrades`; tags `r1-correct` (`ec04fe9`), `r1-instrumented` (`c87d01a`), `r1-handover` (`23dc762`), `r1-handover-2` (`09d6269`, the evaluation version), `r1-final` (`fc8e249`), `r1-submission` (`a70d215`, the version submitted for college evaluation). |
| **R1 – R4** (upgrades) | Planned upgrades: R1 gated baseline update, R2 entropy features, R3 calibrated threshold, R4 fair baseline comparison. R1 and R4 were built; R2 and R3 were deferred. Context tells the two uses of "R1" apart: "R1 (M-04, A-01; …)" in a commit table means the upgrade. |

## Detector configurations (baseline policies)

The baseline is the running mean and standard deviation of each feature. A policy decides which windows are learned into it.

| Legacy label | Command line (legacy alias) | Meaning |
|---|---|---|
| **B0** | `--policy cumulative` (`b0`) | Original cumulative baseline: every scored window is learned, including windows that raised an alert. |
| **B1** | `--policy gated` (`b1`) | Gated cumulative baseline: a window that raises an alert is **not** learned. After 60 consecutive alerting windows, learning resumes ("forced update"), so a lasting change is eventually accepted. |
| **SD floor** | `--sd-floor` | B1 only: each feature's standard deviation is never taken below a minimum (0.5 packets, 2.0 bytes, 0.5 ports, 0.5 IPs), so a near-constant feature can still be scored. Decision D7. |
| **frozen** | `--policy frozen` | Comparator: thresholds come from the 20 warm-up windows and never change. |
| **recovery** | `--recovery N` | B1 only: the number of consecutive alerting windows before learning resumes (default 60). |
| `r0_raw`, `b0`, `b1_nofloor`, `b1_floor`, `frozen`, `b1_floor_r12` | — | Row names in evaluation results produced before 3 Nov 2026: the R0 binary, then the R1 binary with each policy. `b1_floor_r12` is B1 with the floor and recovery 12. Current names, in the same order: `original_prototype`, `cumulative`, `gated`, `gated_sd_floor`, `frozen`, `gated_sd_floor_recovery12`. |
| **B2, B4** | — | Other candidate policies (clipped update, sliding window) considered and deferred. |

## Decisions

| Label | Decision |
|---|---|
| **D4** | Evaluation rules were fixed before any CICIDS2017 result existed (`docs/EVALUATION_METHODOLOGY.md`). |
| **D6** | Use B1, a gated update on the existing cumulative baseline, as the improved policy. |
| **D7** | The SD floor values above, applied to B1 only. |
| **D8** | Time policy: packets earlier than the open window are dropped and counted; an isolated packet more than 60 s in the future is quarantined; an idle gap produces at most 12 empty windows. |
| **D9** | Include the frozen fixed-threshold comparator. |
| **D10** | B1 recovery after 60 windows, with 12 as a sensitivity run. |
| **D13** | The macOS build, screenshots and the CICIDS2017 run are done on the project author's Mac. |
| **I3** | Idle windows (no packets) are reported but never scored or learned. |
| **P1** | The partial final window is reported but never scored or learned. |
| **Q6** | The set of configurations compared in the evaluation. |

## Engineering items

| Label | Item |
|---|---|
| **E1** | Per-window CSV trace (`--trace`, format `netsentinel-trace-v1`). |
| **E2** | Evaluation tools: label alignment, window labelling, metrics. |
| **E3** | Time and window policy (D8, I3, P1) in the `Pipeline` class. |
| **E4** | Packet-parser fixes (NS-07 – NS-10). |
| **E5** | Command-line options. Partially completed: window length and warm-up are not configurable. |
| **E6** | Performance measurement (wall time, packets per second, peak memory). |
| **E7** | Safe ownership of the capture handle (NS-11). |

## Defects found in R0 (NS = NetSentinel defect)

| Label | Defect in R0 |
|---|---|
| **NS-01** | A feature that is constant during warm-up has zero variance, so it can never alert. Unchanged in B0 by decision; handled by B1 with the SD floor. |
| **NS-02** | One packet with a far-future timestamp created hundreds of empty windows. |
| **NS-03** | A first packet with timestamp 0 made a run effectively hang. |
| **NS-04** | A PCAP read error was reported as a clean end of file (fixed in R0: exit code 2). |
| **NS-05** | The partial final window was scored and could raise a false alert. |
| **NS-06** | Idle windows were learned as zeros; IPv6 traffic was reported as a drop. |
| **NS-07** | VLAN-tagged and Linux-cooked captures were not parsed. |
| **NS-08** | Average packet size used the captured length instead of the on-wire length. |
| **NS-09** | Non-first IP fragments: payload bytes were read as port numbers. |
| **NS-10** | A truncated TCP header was counted as port 0. |
| **NS-11** | Copying the capture object caused a use-after-free; reopening leaked a handle. |
| **NS-12** | A default file path pointed to the author's machine. |
| **NS-13** | The test suite could not detect a broken detector or parser. Partially closed. |

## Label families

| Family | Meaning |
|---|---|
| **A-01 … A-08** | Findings of the source audit; older commit messages cite them next to the change that addressed them. |
| **RF-01 … RF-06** | Findings about test and evidence quality, e.g. RF-01 exactly sized test buffers, RF-05 read errors recorded in the trace, RF-06 record which libpcap is linked. |
| **M-01 … M-06** (with hyphen) | Known limits of the statistical method itself (for example slow ramps), documented and not fixed. |
| **M07, M25, …** (no hyphen) | Mutation-test IDs in `tests/mutation/run_mutants.py`: deliberate small bugs used to check that the tests catch them. |
| **FR8** | Functional requirement 8 of the original PRD: configurable window size. |

## Evaluation terms

| Term | Meaning |
|---|---|
| Window | A 5-second slice of traffic, the unit NetSentinel scores. |
| Warm-up | The first 20 windows, learned but not scored. |
| Attack / mixed / attempted / benign / unlabelled window | Window classes from the flow labels; rules in `docs/EVALUATION_METHODOLOGY.md` §3. |
| Primary metrics | Mixed windows excluded; a second variant counts them as attack. |
| Event | A run of consecutive attack-or-mixed windows; detection delay is measured from its first window. |
| Offset | Difference between label time and capture time, measured by `tools/eval/align.py`. |
