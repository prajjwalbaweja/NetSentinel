#!/usr/bin/env bash
# NetSentinel repository verification. Builds in a NEW temporary directory, runs the whole ctest suite, and prints one PASS/FAIL line per check.
# Safety guarantees: never writes inside the repo; never overwrites or deletes any pre-existing file or directory
# (only the temp build dir this script itself created is removed, unless --keep-build); original data/sample.pcap is hashed, never touched.
# Compatible with macOS bash 3.2.   usage: scripts/verify_repository.sh [--repo DIR] [--build-dir NEWDIR] [--keep-build] [--catch2-src DIR] [--strict-warnings] [--sanitize]
# --strict-warnings / --sanitize turn on the opt-in CMake options NS_STRICT_WARNINGS / NS_SANITIZE; each is a SEPARATE verification run.
set -u
REPO=""; BUILD=""; KEEP=0; C2=""; STRICT=0; SAN=0
while [ $# -gt 0 ]; do case "$1" in
  --repo) REPO="$2"; shift 2;; --build-dir) BUILD="$2"; shift 2;; --keep-build) KEEP=1; shift;; --strict-warnings) STRICT=1; shift;; --sanitize) SAN=1; shift;; --catch2-src) C2="$2"; shift 2;;
  -h|--help) sed -n "2,6p" "$0"; exit 0;; *) echo "unknown argument: $1"; exit 2;; esac; done
[ -n "$REPO" ] || REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" 2>/dev/null || { echo "cannot cd to $REPO"; exit 2; }; REPO="$(pwd)"
pass=0; fail=0; warn=0
chk(){ if [ "$2" = "$3" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1   (expected: $3 | got: $2)"; fail=$((fail+1)); fi; }
info(){ echo "INFO  $*"; }
warnl(){ echo "WARN  $*"; warn=$((warn+1)); }
sha(){ if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d" " -f1; else shasum -a 256 "$1" | cut -d" " -f1; fi; }
OS=$(uname -s)
echo "== environment =="; echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"; echo "os: $(uname -srm)"; echo "repo: $REPO"
if command -v git >/dev/null 2>&1 && [ -d .git ]; then
  echo "git commit: $(git rev-parse HEAD)"; if [ -n "$(git status --porcelain 2>/dev/null)" ]; then warnl "working tree has uncommitted changes - results do not correspond to the commit hash above"; else info "working tree clean"; fi
else warnl "not a git checkout - cannot record a commit hash"; fi
need(){ command -v "$1" >/dev/null 2>&1 || { echo "FAIL  missing tool: $1 $2"; exit 3; }; }
if [ "$OS" = Darwin ]; then
  sw_vers 2>/dev/null; echo "arch: $(uname -m)"
  xcode-select -p >/dev/null 2>&1 || { echo "FAIL  Xcode Command Line Tools missing: xcode-select --install"; exit 3; }
  need brew "(install Homebrew)"; need cmake "(brew install cmake)"; need pkg-config "(brew install pkg-config)"
  brew list libpcap >/dev/null 2>&1 || { echo "FAIL  libpcap missing: brew install libpcap"; exit 3; }
  export PKG_CONFIG_PATH="$(brew --prefix libpcap)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
  info "PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
else need cmake ""; need pkg-config ""; fi
need python3 "(needed by golden/oracle/fixture tests)"
c++ --version 2>&1 | head -1; cmake --version | head -1; python3 --version
echo -n "libpcap via pkg-config: "; pkg-config --modversion libpcap || { echo "NOT FOUND"; fail=$((fail+1)); }
echo; echo "== original sample vs audited manifest (identification only; nothing is written) =="
if [ -f data/sample.pcap ]; then
  S=$(sha data/sample.pcap); info "data/sample.pcap sha256 = $S  ($(wc -c < data/sample.pcap | tr -d " ") bytes)"
  M=$(grep "  data/sample.pcap\$" MANIFEST.sha256 2>/dev/null | cut -d" " -f1)
  if [ "$S" = "$M" ]; then info "matches the AUDITED ORIGINAL recorded in MANIFEST.sha256"; else warnl "data/sample.pcap DIFFERS from the audited original (manifest says ${M:-<no entry>}); golden_sample_original will fail - that is the intended signal"; fi
  if [ -f tests/data/regenerated/sample_regenerated.pcap ]; then
    R=$(sha tests/data/regenerated/sample_regenerated.pcap); if [ "$S" = "$R" ]; then info "original == regenerated copy (byte-identical)"; else info "original and regenerated copy DIFFER: both are tested separately against their own goldens"; fi; fi
else warnl "data/sample.pcap absent - original-sample tests will fail; regenerated copy is still tested separately"; fi
echo; echo "== audited files changed since the audited snapshot (informational) =="
ch=0; if [ -f MANIFEST.sha256 ]; then while read -r h f; do [ -f "$f" ] || { echo "  missing: $f"; ch=$((ch+1)); continue; }; [ "$(sha "$f")" = "$h" ] || { echo "  modified: $f"; ch=$((ch+1)); }; done < <(sed "s/  / /" MANIFEST.sha256); fi; info "$ch audited file(s) differ from MANIFEST.sha256"
echo; echo "== configure / build (new temp dir) =="
if [ -n "$BUILD" ]; then
  if [ -e "$BUILD" ] && [ -n "$(ls -A "$BUILD" 2>/dev/null)" ]; then echo "FAIL  --build-dir $BUILD exists and is not empty; refusing to reuse or delete it"; exit 3; fi
  mkdir -p "$BUILD"; OWN=0
else BUILD="$(mktemp -d "${TMPDIR:-/tmp}/netsentinel_verify.XXXXXX")"; OWN=1; fi
info "build dir: $BUILD"
XOPTS=""; [ $STRICT -eq 1 ] && XOPTS="$XOPTS -DNS_STRICT_WARNINGS=ON"; [ $SAN -eq 1 ] && XOPTS="$XOPTS -DNS_SANITIZE=ON"
info "mode: default$( [ $STRICT -eq 1 ] && echo " +strict-warnings")$( [ $SAN -eq 1 ] && echo " +sanitize")"
cmake -S . -B "$BUILD" $XOPTS ${C2:+-DFETCHCONTENT_SOURCE_DIR_CATCH2="$C2"} > "$BUILD/configure.log" 2>&1; chk "cmake configure rc" $? 0
cmake --build "$BUILD" -j4 > "$BUILD/build.log" 2>&1; chk "cmake build rc" $? 0
if [ $STRICT -eq 1 ]; then chk "strict-warnings build: warning count (project targets)" "$(grep -c "warning:" "$BUILD/build.log")" 0; else info "warning lines with the project default flags: $(grep -ci warning "$BUILD/build.log") (default flags contain no -Wall: weak evidence; use --strict-warnings)"; fi
info "linked libpcap:"; if [ "$OS" = Darwin ]; then otool -L "$BUILD/netsentinel" | grep -i pcap | sed "s/^/        /"; else ldd "$BUILD/netsentinel" 2>/dev/null | grep -i pcap | sed "s/^/        /"; fi
echo; echo "== required tests exist (fixtures: sample original+regenerated, gap, boundary, truncated x4, corrupt, empty, missing) =="
(cd "$BUILD" && ctest -N) > "$BUILD/ctest_list.txt" 2>&1
for t in StatEngineTests fixtures_verify fixtures_regenerate golden_sample_original golden_sample_regenerated golden_gap golden_boundary golden_empty golden_corrupt golden_trunc_global golden_trunc_data golden_trunc_hdr golden_trunc_mid golden_missing oracle_sample_original oracle_sample_regenerated oracle_gap oracle_boundary; do
  grep -q ": $t\$" "$BUILD/ctest_list.txt" && r=registered || r=ABSENT; chk "test registered: $t" $r registered; done
echo; echo "== run ctest =="
(cd "$BUILD" && ctest --output-on-failure) > "$BUILD/ctest_run.txt" 2>&1; rc=$?
grep -E "Test +#[0-9]+:" "$BUILD/ctest_run.txt" | sed "s/^ */      /"
chk "ctest overall rc" $rc 0
grep -E "tests passed|tests failed" "$BUILD/ctest_run.txt"
if [ $rc -ne 0 ]; then echo "---- failing output ----"; grep -vE "^ *[0-9]+/[0-9]+ Test +#.*Passed" "$BUILD/ctest_run.txt" | head -60; fi
echo; echo "== unit test binary run directly (independent of ctest wiring) =="
"$BUILD/netsentinel_tests" > "$BUILD/unit.txt" 2>&1; chk "netsentinel_tests rc" $? 0; chk "Catch2 summary" "$(grep -E "All tests passed|test cases" "$BUILD/unit.txt" | tail -1)" "All tests passed (53 assertions in 5 test cases)"
if [ $SAN -eq 1 ]; then chk "sanitizer reports in ctest output" "$(grep -ciE "AddressSanitizer|runtime error|LeakSanitizer" "$BUILD/ctest_run.txt" "$BUILD/unit.txt" | awk -F: "{s+=\$2} END{print s+0}")" 0; fi
echo; echo "== summary =="
echo "commit: $(git rev-parse HEAD 2>/dev/null || echo n/a)   os: $OS   pass=$pass fail=$fail warn=$warn"
if [ $OWN -eq 1 ] && [ $KEEP -eq 0 ]; then rm -rf "$BUILD"; info "removed the temp build dir this script created"; else info "build dir kept: $BUILD"; fi
[ $fail -eq 0 ]
