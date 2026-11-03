#!/usr/bin/env python3
"""Characterization (golden) test runner.  usage: run_golden.py --exe EXE --root REPO_ROOT --name NAME [--update [--force]]
Runs  EXE <relative pcap>  with cwd=REPO_ROOT (so printed paths are machine-independent) and compares:
  exit code      exactly
  stdout         token-wise: integer tokens exactly, floating tokens within rel 2e-5 (guards last-digit printing differences across platforms)
  stderr         exactly against NAME.stderr, OR (manifest column 4 != "-") must CONTAIN the given substring (libpcap error text is library-defined)
tests/golden/MANIFEST.tsv columns: name, pcap, expect_exit, stderr_contains|-, tags   (tags are free-text notes on the pinned behaviour)
--update writes goldens from the given binary; refuses to overwrite existing goldens without --force. ctest never uses --update."""
import sys, os, re, subprocess, argparse
ap = argparse.ArgumentParser(); ap.add_argument("--exe", required=True); ap.add_argument("--root", required=True); ap.add_argument("--name", required=True)
ap.add_argument("--update", action="store_true"); ap.add_argument("--force", action="store_true"); a = ap.parse_args()
root = os.path.abspath(a.root); gd = os.path.join(root, "tests/golden")
rows = [l.rstrip("\n").split("\t") for l in open(os.path.join(gd, "MANIFEST.tsv")) if l.strip() and not l.startswith("#")]
row = next((r for r in rows if r[0] == a.name), None)
if row is None: print("no such golden: " + a.name); sys.exit(2)
name, pcap, exp_exit, contains, tags = row[0], row[1], int(row[2]), row[3], row[4] if len(row) > 4 else ""
p = subprocess.run([a.exe, pcap], cwd=root, capture_output=True, text=True)
so = p.stdout.replace("\r\n", "\n"); se = p.stderr.replace("\r\n", "\n")
fo, fe = os.path.join(gd, name + ".stdout"), os.path.join(gd, name + ".stderr")
if a.update:
    for f, c in ((fo, so), (fe, se if contains == "-" else None)):
        if c is None: continue
        if os.path.exists(f) and not a.force: print("REFUSING to overwrite " + f); sys.exit(3)
        open(f, "w", newline="\n").write(c)
    print("wrote goldens for %s (exit %d from the given binary)" % (name, p.returncode)); sys.exit(0)
NUM = re.compile(r"[-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?")
def cmp_stdout(got, want):
    gl, wl = got.split("\n"), want.split("\n")
    if len(gl) != len(wl): return None, "line count differs: got %d want %d" % (len(gl), len(wl))
    maxrel = 0.0; exact = True
    for i, (g, w) in enumerate(zip(gl, wl), 1):
        if g == w: continue
        exact = False
        if NUM.sub("#", g) != NUM.sub("#", w): return None, "line %d text differs:\n   got:  %s\n   want: %s" % (i, g, w)
        for x, y in zip(NUM.findall(g), NUM.findall(w)):
            if x == y: continue
            if not re.search(r"[.eE]", x + y): return None, "line %d integer differs: %s vs %s" % (i, x, y)
            rel = abs(float(x) - float(y)) / max(abs(float(y)), 1e-300); maxrel = max(maxrel, rel)
            if rel > 2e-5: return None, "line %d number differs beyond tolerance: %s vs %s" % (i, x, y)
    return ("EXACT" if exact else "WITHIN-TOLERANCE(max_rel=%.1e)" % maxrel), None
errs = []
if p.returncode != exp_exit: errs.append("exit code: got %d want %d" % (p.returncode, exp_exit))
if not os.path.exists(fo): errs.append("missing golden file " + fo); mode = "n/a"
else:
    mode, e = cmp_stdout(so, open(fo).read())
    if e: errs.append("stdout: " + e)
if contains != "-":
    if contains not in se: errs.append("stderr must contain %r, got %r" % (contains, se.strip()))
else:
    want = open(fe).read() if os.path.exists(fe) else None
    if want is None: errs.append("missing golden file " + fe)
    elif se != want: errs.append("stderr differs:\n   got:  %r\n   want: %r" % (se, want))
print("golden[%s] exit=%d stdout=%s stderr=%s tags=%s" % (name, p.returncode, mode, ("contains-ok" if contains != "-" and not errs else "exact" if contains == "-" else "FAIL"), tags or "-"))
for e in errs: print("  FAIL", e)
sys.exit(1 if errs else 0)
