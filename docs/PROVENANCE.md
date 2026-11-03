# Provenance of the audited original tree

Generated 2026-10-26 from the working copy of the uploaded files. Facts below were OBSERVED; interpretations are marked.

- Audited commit: `378e0622966cd60139531984688fe16450ed6e2f`. It contains exactly the 29 files in MANIFEST.sha256, byte-identical to the uploads.
- Directory layout was RECONSTRUCTED from `source_inventory.txt` (uploads were flat); file contents were not altered.
- `.DS_Store` appears in source_inventory.txt but was never uploaded; it is intentionally not in the tree.
- No upload carried a hash manifest, so "all from one snapshot" cannot be proven. Batches differ by observed modification time:

| Batch | Observed mtime | Files |
|---|---|---|
| A | 1979-12-31 (archive placeholder) | 20 files: all headers, CMakeLists.txt, tests/README.md, generate_sample_pcap.py, tests/test_stat_engine.cpp |
| B | 2026-10-25 17:37 | 7 src/*.cpp + source_inventory.txt |
| C | 2026-10-26 06:57 (upload time) | data/sample.pcap |

Consistency evidence (not proof of a single snapshot): batch A and B files compile and link together with 0 errors; 53 unit assertions pass; C++ output matches an independent Python oracle (initial audit evidence).

## Per-file hashes

See MANIFEST.sha256 (sha256sum / shasum -a 256 -c compatible).
