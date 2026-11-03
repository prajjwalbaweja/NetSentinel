# Mutation check of the original characterization suite (Linux, 2026-10-26)

> Historical result for the original prototype. The current mutation status (partially closed: 28 mutants, 18 killed,
> 0 survived, 10 invalid) is in `docs/CHANGES.md`.

Tool: `tests/mutation/run_mutants.py` (works on a temp copy; the repo is never modified). 25 mutants applied one at a time, full `ctest` (17 tests) each time.
Predictions (`kill` / `survive-equivalent` / `survive-gap`) are fixed in the script source and were written before the first run; **all 25 predictions matched the outcome**. The author wrote both predictions and tests, so this is not independent review.

**Result: 18 killed, 7 survived, 0 invalid.**

| Survivor | Mutation | Class | Meaning / follow-up |
|---|---|---|---|
| M07 | variance epsilon 1e-6 -> 1e-5 | gap | No test has a baseline variance in [1e-6, 1e-5). Needs a StatEngine unit test with such variance (unit-level follow-up; added later). |
| M12 | `|z| > 3.0` -> `>=` | equivalent | z exactly equal to 3.0 is practically unreachable; not worth a test. |
| M13 | scorer drops its own `isWarmedUp()` check | equivalent | `zScore()` already returns NaN when not warmed up; the check is redundant. |
| M15 | count dst port for every protocol | gap | No non-TCP/UDP (ICMP) fixture. Parsing follow-up. |
| M16 | UDP port parsing disabled | gap | No UDP fixture (UDP lines 72-74 were never executed in the initial audit either). Parsing follow-up. |
| M17 | ethertype IPv4 check removed | gap | The ARP-like fixture frames are rejected anyway by the IPv4 version check. Needs a frame that passes everything except the ethertype. Parsing follow-up. |
| M25 | captured length -> original length | gap | No snaplen-truncated record in any fixture (added later). |

Killed mutants include: threshold 2.9 / 3.1 / 2.0 (2.9 and 3.1 are killed ONLY by the boundary fixture), warm-up 19 / 21, window 4 s, epsilon 0.3, population variance,
Welford delta2 bug, ignoring negative z, `>=`->`>` window close, update-before-score, missing EOF window, dedup to one feature, wrong dst IP/port offsets, size off by 14.

Raw logs of the three chunks: see `docs/mutation_logs/`.

## Addendum: read-error exit code (2026-10-26)

Three mutants were added for the read-error behaviour (predictions fixed in the script before the run): M26 read error never recorded, M27 clean EOF also flagged as a read error,
M28 read-error exit code 2 -> 1. **All three killed**; M27 is killed by every clean-EOF golden, which is what protects "clean EOF stays exit 0".
Totals now: 28 mutants, 21 killed, 7 survived (the survivors listed above are unchanged). Log: `docs/mutation_logs/chunk4.log`.
