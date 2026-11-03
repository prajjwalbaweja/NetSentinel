# tests/

| Directory / file | What it tests | CTest names |
|---|---|---|
| `test_stat_engine.cpp` | Welford mean/variance, warm-up, variance guard (original tests, unchanged) | `StatEngineTests` |
| `unit/` | capture handle ownership; extractor (link layers, on-wire length, fragments, truncated headers, exact-size buffers for ASan); pipeline time and window policy (late and far-future packets, idle-gap cap, idle and partial windows, fractional timestamps); baseline policies (cumulative, gated, recovery, SD floor, frozen threshold) | `UnitTests` |
| `golden/` | characterization of console output and exit codes (regenerated deliberately after the time and window policy change; see MANIFEST tags) | `golden_*` |
| `oracle/` | independent Python reading of the time/window contract, cross-checked window by window | `oracle_*`, `oracle_audit_*` |
| `data/audit/`, `regression/check_audit.py` | audit fixtures and closure checks for the defects of the original prototype | `audit_*` |
| `regression/check_cli_trace.py` | command line, exit codes, CSV trace, trace golden | `cli_and_trace` |
| `eval/test_eval_tools.py` | evaluator (hand-labelled case), original-prototype console parser, CICFlowMeter-format stand-in end to end | `eval_tools` |
| `fixtures/` | fixture generators and SHA-256 verification | `fixtures_verify`, `fixtures_regenerate` |
