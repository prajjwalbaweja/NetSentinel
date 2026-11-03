# tests/data — fixtures

| Path | What | Provenance |
|---|---|---|
| `../../data/sample.pcap` | **ORIGINAL** reference sample, as uploaded by the project owner | Recorded in the root `MANIFEST.sha256`. Never regenerated, never overwritten. |
| `regenerated/sample_regenerated.pcap` | Output of `generate_sample_pcap.py` run from this repo | **Separate file.** When it was generated it was byte-identical to the original (same SHA-256); the identity is reported, not assumed, and nothing enforces it in future. |
| `synthetic/*.pcap` | Edge-case fixtures from `tests/fixtures/make_fixtures.py` | Deterministic; see that script for each fixture. |

Rules: tools in this repo never overwrite an existing fixture (`--force` is required and is never used by tests).
Verify with `ctest -R fixtures` or `shasum -a 256 -c tests/data/MANIFEST.sha256` from the repo root.
