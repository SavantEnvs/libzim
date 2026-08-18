#!/usr/bin/env bash
#
# libzim/mayhem/test.sh -- RUN libzim's own upstream gtest suite (built by
# mayhem/build.sh in mayhem-build/test/, one dynamically-linked binary per
# test/*.cpp file) PLUS the direct KAT probe (mayhem/kat/kat_probe.cpp) against the
# committed fixture mayhem/fixtures/tiny.zim, and emit one CTRF summary. exit 0 iff
# nothing failed.
#
# Two layers, and BOTH are load-bearing here (unlike a single combined test runner):
#
#  1) Each test/*.cpp file (log, uuid, compression, dirent, creator, archive, ...;
#     ~28 files, ~140+ individual TEST/TEST_F cases with -Dtest_data_dir=none --
#     see mayhem/build.sh) compiles to its OWN gtest binary under mayhem-build/test/.
#     We invoke each binary DIRECTLY (never `meson test`) and parse gtest's OWN
#     "[  PASSED  ] N tests." / "[  FAILED  ] N tests," summary lines from its stdout.
#     This is deliberately NOT "run via `meson test`, trust its exit-code summary" --
#     that pattern was proven sabotage-blind on checkouts/pkgconf (meson/ctest judge a
#     case purely by the launched process's exit code, and if the shim `_exit(0)`s that
#     process before it runs a single assertion, the runner still reports "OK"). Each
#     binary here IS the actual gtest process (no wrapper in between), and if
#     verify-repo's LD_PRELOAD sabotage shim neuters it, it exits before printing any
#     "[  PASSED  ]"/"[  FAILED  ]" line at all -- our parser then correctly reports
#     "no gtest summary" as a FAILURE (see the loop below), not a silent pass.
#
#  2) mayhem/kat/kat_probe.cpp -- a small, separate, dynamically-linked binary that
#     opens the committed fixture mayhem/fixtures/tiny.zim through the SAME public
#     Archive/Entry/Item/Blob API our fuzz harnesses use, and asserts exact values
#     (entry count, an item's title/mimetype/content, a redirect's target, a metadata
#     value) lifted straight from how mayhem/kat/genzim.cpp built that fixture. This
#     covers the read path directly, independent of whatever the upstream suite does.
#
# This script only RUNS things; mayhem/build.sh did the building.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

TEST_BUILD="$SRC/mayhem-build/test"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -d "$TEST_BUILD/test" ]; then
  echo "missing $TEST_BUILD/test -- run mayhem/build.sh first" >&2
  emit_ctrf "libzim-gtest+kat" 0 1 0
  exit 2
fi

PASSED=0; FAILED=0; SKIPPED=0

# ── 1) upstream's own gtest binaries, run DIRECTLY (see header) ─────────────────────
echo "=== running libzim's gtest binaries under mayhem-build/test/ ==="
bin_count=0
for bin in "$TEST_BUILD"/test/*; do
  [ -x "$bin" ] && [ -f "$bin" ] || continue
  bin_count=$(( bin_count + 1 ))
  name="$(basename "$bin")"
  echo "--- $name ---"
  out="$("$bin" 2>&1)"; rc=$?
  echo "$out"

  p="$(printf '%s\n' "$out" | sed -n 's/^\[  PASSED  \] \([0-9][0-9]*\) test.*/\1/p' | tail -1)"
  f="$(printf '%s\n' "$out" | sed -n 's/^\[  FAILED  \] \([0-9][0-9]*\) test.*/\1/p' | tail -1)"

  if [ -z "$p" ] && [ -z "$f" ]; then
    echo "FAIL: $name produced no gtest summary (neutered, crashed rc=$rc, or broken binary)" >&2
    FAILED=$(( FAILED + 1 ))
    continue
  fi
  : "${p:=0}" "${f:=0}"
  PASSED=$(( PASSED + p ))
  FAILED=$(( FAILED + f ))
done

if [ "$bin_count" -eq 0 ]; then
  echo "FAIL: no gtest binaries found under $TEST_BUILD/test -- build.sh did not produce the suite" >&2
  emit_ctrf "libzim-gtest+kat" 0 1 0
  exit 2
fi
echo "=== gtest subtotal across $bin_count binaries: passed=$PASSED failed=$FAILED ==="

# ── 2) direct KAT probe against the committed fixture (sabotage-detecting; see header) ──
KAT_BIN="$TEST_BUILD/kat_probe"
FIXTURE="$SRC/mayhem/fixtures/tiny.zim"
if [ ! -x "$KAT_BIN" ]; then
  echo "FAIL: missing $KAT_BIN -- run mayhem/build.sh first" >&2
  FAILED=$(( FAILED + 1 ))
elif [ ! -f "$FIXTURE" ]; then
  # Unconditional: a missing fixture is a failure, never a skip.
  echo "FAIL: missing fixture $FIXTURE" >&2
  FAILED=$(( FAILED + 1 ))
else
  echo "=== running: kat_probe $FIXTURE ==="
  kat_out="$("$KAT_BIN" "$FIXTURE" 2>&1)"; kat_rc=$?
  echo "$kat_out"
  kat_pass=$(printf '%s\n' "$kat_out" | grep -c '^KAT PASS:')
  kat_fail=$(printf '%s\n' "$kat_out" | grep -c '^KAT FAIL:')
  if [ "$kat_pass" -eq 0 ] && [ "$kat_fail" -eq 0 ]; then
    echo "FAIL: kat_probe produced no KAT PASS/FAIL lines (neutered or crashed rc=$kat_rc)" >&2
    FAILED=$(( FAILED + 1 ))
  else
    PASSED=$(( PASSED + kat_pass ))
    FAILED=$(( FAILED + kat_fail ))
    if [ "$kat_rc" -ne 0 ] && [ "$kat_fail" -eq 0 ]; then
      echo "FAIL: kat_probe exited $kat_rc despite reporting 0 KAT failures -- treating as inconsistent/failed" >&2
      FAILED=$(( FAILED + 1 ))
    fi
  fi
fi

# Plausibility floor: empirically, with -Dtest_data_dir=none, libzim's 26 gtest binaries
# report 129 passed/0 failed gtest cases (find/iterator report 0 -- entirely gated on
# WITH_TEST_DATA) plus 10 KAT PASS lines = 139 total. 100 is a floor with real margin --
# it only trips on a structural break (wrong build dir, binaries missing), not normal
# upstream test-count drift.
MIN_EXPECTED=100
TOTAL=$(( PASSED + FAILED + SKIPPED ))
if [ "$TOTAL" -lt "$MIN_EXPECTED" ]; then
  echo "FAIL: only $TOTAL total test results (passed+failed+skipped), expected >= $MIN_EXPECTED -- suite did not run fully" >&2
  FAILED=$(( FAILED + 1 ))
fi

echo "=== results: libzim gtest+KAT passed=$PASSED failed=$FAILED skipped=$SKIPPED ==="
emit_ctrf "libzim-gtest+kat" "$PASSED" "$FAILED" "$SKIPPED"
