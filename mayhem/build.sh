#!/usr/bin/env bash
#
# libzim/mayhem/build.sh -- build two libFuzzer harnesses over the ZIM archive reader
# (+ standalone reproducers), AND libzim's own upstream gtest suite + a KAT probe for
# mayhem/test.sh.
#
#   fuzz_archive     -- zim::Archive(fd) + a bounded walk of the dirent table (path,
#                       title, redirect resolution, item mimetype). The "well-formed
#                       ZIM container" surface: header, mimetype list, url/title
#                       pointer lists, directory-entry table.
#   fuzz_entry_read  -- same, PLUS Item::getData() over a bounded byte budget, which
#                       drives the cluster/zstd (and legacy LZMA) decompression path.
#
# Both harnesses materialize the fuzzer bytes in an anonymous memfd_create(2) file (no
# filesystem path at all -- see mayhem/harnesses/fuzz_archive.cpp for why) and open it
# via libzim's Archive(int fd) constructor.
#
# TWO independent meson build directories (SPEC 6.2 item 10 / 6.3), same shape as
# checkouts/pkgconf's mayhem/build.sh (also a meson C/C++ project):
#   mayhem-build/fuzz/  sanitized (ASan+UBSan halting, unconditionally +fuzzer-no-link)
#                       + DWARF<=3, -Ddefault_library=static (libzim.a self-contained,
#                       no .so to carry into /mayhem).
#   mayhem-build/test/  NORMAL flags, default_library=shared (meson default) so the
#                       gtest suite binaries AND the KAT probe are DYNAMICALLY linked
#                       against libzim.so -- reachable by verify-repo's LD_PRELOAD
#                       sabotage check (see mayhem/test.sh for why this matters).
#
# Both builds disable xapian (-Dwith_xapian=false): it's an optional full-text-search
# index, not part of the ZIM-parsing surface we fuzz, and dropping it means ICU
# (required only when xapian is found) is never needed either -- keeps the apt closure
# small (SPEC 6.2 "disable optional features you don't need"). liblzma/libzstd resolve
# from apt -dev packages (pkg-config finds them; libzim's meson.build only falls back
# to its subprojects/{zstd,liblzma}.wrap when the system dep is absent -- verified this
# doesn't trigger with the packages mayhem/Dockerfile installs, so there is nothing to
# vendor for the air-gapped re-run beyond those apt packages). The gtest dependency
# resolves the same way from apt's libgtest-dev (meson's built-in "gtest" special
# dependency self-compiles the source apt drops under /usr/src/googletest when no
# pkg-config/cmake package is found -- no subprojects/gtest.wrap fetch either).
#
# Test data: libzim ships NO committed .zim fixtures -- test/tools.cpp downloads real
# Wikipedia-derived archives from a GitHub release at test time (network + gigabytes we
# don't want in an air-gapped image). We build with -Dtest_data_dir=none, which only
# skips the handful of test files gated on WITH_TEST_DATA (find.cpp, part of
# archive.cpp, suggestion.cpp, iterator.cpp); the rest of the ~28 test files build their
# own ZIM fixtures on the fly via the Creator API and run unconditionally. Separately,
# mayhem/fixtures/tiny.zim (committed) was generated ONCE with mayhem/kat/genzim.cpp
# against a normal build of this same library -- see that file's header -- and is used
# both as a KAT fixture (mayhem/kat/kat_probe.cpp) and as fuzzer starter seeds.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' -- must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# Always ensure the LIBRARY gets SanitizerCoverage instrumentation, regardless of the base
# image's default or an empty override -- otherwise Mayhem sees 0 edges from the parser
# despite the harness translation unit itself being instrumented via $LIB_FUZZING_ENGINE.
case "$SANITIZER_FLAGS" in
  *fuzzer-no-link*) ;;
  *) SANITIZER_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link" ;;
esac
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

FUZZ_BUILD="$SRC/mayhem-build/fuzz"
TEST_BUILD="$SRC/mayhem-build/test"

COMMON_OPTS=(-Dwith_xapian=false -Dexamples=false -Ddoc=false -Dwerror=false)

# ── 1) Sanitized build: libzim.a + the 2 harnesses, DWARF<=3, static-linked ───────────
# --wipe so a re-run (offline PATCH tier, SPEC 6.2 item 9) reconfigures cleanly if a
# previous partial mayhem-build/fuzz exists; plain `meson setup` refuses a second setup
# on an already-configured dir without --reconfigure/--wipe.
setup_meson() {
  local builddir="$1"; shift
  if [ -d "$builddir" ]; then
    meson setup --wipe "$builddir" "$@" \
      || { cat "$builddir/meson-logs/meson-log.txt" 2>/dev/null; exit 1; }
  else
    meson setup "$builddir" "$@" \
      || { cat "$builddir/meson-logs/meson-log.txt" 2>/dev/null; exit 1; }
  fi
}

CC="$CC" CXX="$CXX" \
  CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" CXXFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" LDFLAGS="$SANITIZER_FLAGS" \
  setup_meson "$FUZZ_BUILD" "${COMMON_OPTS[@]}" -Dtests=false -Ddefault_library=static
ninja -C "$FUZZ_BUILD" -j"$MAYHEM_JOBS"
echo "built sanitized libzim.a (mayhem-build/fuzz/)"

LIBZIM_A="$FUZZ_BUILD/src/libzim.a"
[ -f "$LIBZIM_A" ] || { echo "FATAL: $LIBZIM_A missing after ninja build" >&2; exit 1; }

# zstd/lzma/pthread: the system shared libs libzim.a itself was compiled against.
EXTRA_LIBS="-lzstd -llzma -lpthread"

# Standalone driver object, built once, linked into every harness's -standalone binary.
# Compiled as C (-x c): a C++ harness otherwise mangles its LLVMFuzzerTestOneInput symbol.
STANDALONE_OBJ="/tmp/standalone_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o "$STANDALONE_OBJ"

# -I"$FUZZ_BUILD/include": meson generates the public zim/zim_config.h (LIBZIM_EXPORT_DLL
# etc.) into the BUILD dir, mirroring include/zim/ -- it does not exist under $SRC/include.
HARNESS_INCLUDES=(-I"$SRC/include" -I"$FUZZ_BUILD/include")
for h in fuzz_archive fuzz_entry_read; do
  echo "=== building /mayhem/$h ==="
  $CXX -std=c++17 $SANITIZER_FLAGS $DEBUG_FLAGS "${HARNESS_INCLUDES[@]}" \
      "$SRC/mayhem/harnesses/$h.cpp" $LIB_FUZZING_ENGINE "$LIBZIM_A" $EXTRA_LIBS \
      -o "/mayhem/$h"

  $CXX -std=c++17 $SANITIZER_FLAGS $DEBUG_FLAGS "${HARNESS_INCLUDES[@]}" \
      "$SRC/mayhem/harnesses/$h.cpp" "$STANDALONE_OBJ" "$LIBZIM_A" $EXTRA_LIBS \
      -o "/mayhem/$h-standalone"
  echo "built $h (+ standalone)"
done

# ── 2) NORMAL-flags build: libzim.so + upstream's gtest suite ─────────────────────────
# Independent build dir, NO $SANITIZER_FLAGS/$DEBUG_FLAGS -- a clean functional-oracle
# build (default_library=shared, meson's default) so every test executable and the KAT
# probe below are DYNAMICALLY linked against libzim.so (needed for the sabotage check;
# see mayhem/test.sh for why `meson test`'s own pass/fail is NOT used as the oracle).
setup_meson "$TEST_BUILD" "${COMMON_OPTS[@]}" -Dtests=true -Dtest_data_dir=none
ninja -C "$TEST_BUILD" -j"$MAYHEM_JOBS"
echo "built normal-flags libzim.so + gtest suite (mayhem-build/test/)"

any_test_bin=0
for t in "$TEST_BUILD"/test/*; do
  [ -x "$t" ] && [ -f "$t" ] || continue
  any_test_bin=1
  file "$t" | grep -q 'dynamically linked' \
    || { echo "FATAL: $t is not dynamically linked -- sabotage check could not reach it" >&2; exit 1; }
done
[ "$any_test_bin" -eq 1 ] || { echo "FATAL: no gtest binaries produced under $TEST_BUILD/test" >&2; exit 1; }

# ── 3) KAT probe: normal flags, links against the SAME libzim.so as the test build ────
TEST_LIBZIM_DIR="$TEST_BUILD/src"
$CXX -std=c++17 -I"$SRC/include" -I"$TEST_BUILD/include" "$SRC/mayhem/kat/kat_probe.cpp" \
    -L"$TEST_LIBZIM_DIR" -Wl,-rpath,"$TEST_LIBZIM_DIR" -lzim \
    -o "$TEST_BUILD/kat_probe"
file "$TEST_BUILD/kat_probe" | grep -q 'dynamically linked' \
  || { echo "FATAL: kat_probe is not dynamically linked" >&2; exit 1; }

# ── 4) fixtures/dicts referenced by the Mayhemfiles must actually exist in /mayhem ────
[ -f "$SRC/mayhem/fixtures/tiny.zim" ] || { echo "FATAL: mayhem/fixtures/tiny.zim missing (see mayhem/kat/genzim.cpp)" >&2; exit 1; }

echo "build.sh complete:"
ls -la /mayhem/fuzz_archive /mayhem/fuzz_entry_read \
       /mayhem/fuzz_archive-standalone /mayhem/fuzz_entry_read-standalone \
       "$TEST_BUILD/kat_probe"
