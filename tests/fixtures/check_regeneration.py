#!/usr/bin/env python3
"""Regenerate every fixture (synthetic fixtures, regenerated sample, audit fixtures) into a TEMP dir (never into the repo)
and compare SHA-256 with tests/data/MANIFEST.sha256."""
import sys, os, subprocess, hashlib, tempfile
root = os.path.abspath(sys.argv[1]); py = sys.executable
man = {}
for l in open(os.path.join(root, "tests/data/MANIFEST.sha256")):
    h, p = l.strip().split("  ", 1); man[p] = h
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
bad = 0
with tempfile.TemporaryDirectory() as t:
    subprocess.run([py, os.path.join(root, "tests/fixtures/make_fixtures.py"), os.path.join(t, "synthetic")], check=True, stdout=subprocess.DEVNULL)
    subprocess.run([py, os.path.join(root, "generate_sample_pcap.py"), os.path.join(t, "sample_regenerated.pcap")], check=True, stdout=subprocess.DEVNULL)
    # Audit fixtures are listed in the manifest too; regenerate them with their own generator.
    subprocess.run([py, os.path.join(root, "tests/fixtures/make_audit_fixtures.py"), os.path.join(t, "audit")], check=True, stdout=subprocess.DEVNULL)
    for p, h in sorted(man.items()):
        name = os.path.basename(p)
        sub = "synthetic" if "/synthetic/" in p else ("audit" if "/audit/" in p else "")
        src = os.path.join(t, sub, name) if sub else os.path.join(t, name)
        got = sha(src) if os.path.exists(src) else "(not generated)"
        ok = got == h; bad += (not ok); print(("ok       " if ok else "MISMATCH ") + p + ("" if ok else "\n   manifest %s\n   regenerated %s" % (h, got)))
sys.exit(1 if bad else 0)
