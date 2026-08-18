# Finding: cumulative memory leak reading a malformed item's data (OOM under repeated processing)

**Target:** `fuzz_entry_read`
**Class:** memory leak → out-of-memory (DoS on a long-lived process), not a single-shot decompression bomb
**Status:** real, reproduced; not filed upstream yet

## Reproduction

```
/mayhem/fuzz_entry_read-standalone mayhem/fuzz_entry_read/known-findings/oom-leak-on-malformed-getdata/repro-1
```

A single execution of either `repro-1` or `repro-2` completes normally (observed peak RSS ~29MB,
exit 0) — this is NOT a classic single-input decompression bomb. The bug only shows up when the
**same** input is processed **repeatedly in one process**, which is exactly libFuzzer's/Mayhem's
persistent-mode execution model (many `LLVMFuzzerTestOneInput` calls per process):

```
mkdir -p /tmp/corpus && cp repro-1 /tmp/corpus/
/mayhem/fuzz_entry_read -runs=200000 -max_total_time=60 /tmp/corpus/
```

This reliably hits libFuzzer's `-rss_limit_mb` (default 2048) and aborts with
`SUMMARY: libFuzzer: out-of-memory` within a few hundred milliseconds (thousands of iterations),
i.e. the process leaks on the order of ~1 MB per call to `LLVMFuzzerTestOneInput` on this specific
input.

## Isolation (what was ruled out)

- **Not a harness fd leak**: `/proc/<pid>/fd` count stayed constant (6) across the run while RSS
  climbed — the memfd created and closed each iteration (see `mayhem/harnesses/fuzz_entry_read.cpp`)
  is not the leak source.
- **Not triggered by `fuzz_archive`** (same Archive-construction + dirent-walk code, but never calls
  `Item::getData()`): replaying `mayhem/fuzz_archive/testsuite/tiny.zim` 22,836 times in 16s shows no
  growth and no OOM.
- **Not triggered by a well-formed archive**: replaying the clean, valid
  `mayhem/fuzz_entry_read/testsuite/tiny.zim` (same harness, same decompression code path) 26,987
  times in 16s shows no growth and no OOM either.
- **Is triggered specifically by these two malformed variants** of `tiny.zim` (each differs from the
  clean fixture by a small number of mutated bytes in the dirent/cluster region past offset ~80 —
  see `cmp -l` against `mayhem/fixtures/tiny.zim`), and specifically by the harness's
  `Item::getData(offset, size)` call on the mutated `"data"` item.

This isolates the leak to `zim::Item::getData()` (or something it triggers, e.g. the cluster
decompression/cache path in `src/cluster.cpp`) on this class of malformed input: some field the
mutation touches makes each `getData()` call retain memory that a well-formed archive's call does
not.

## Impact

A process that repeatedly opens and reads many attacker-influenced ZIM archives (e.g. a server like
`kiwix-serve`, or any pipeline that processes many small/untrusted `.zim` files in one long-lived
process) can be driven to OOM by feeding it copies of this malformed shape, without needing a single
large/pathological file — the effect is cumulative.

## Suggested direction (not root-caused to an exact line)

Audit `Item::getData()`'s / the cluster decompression path's error/exception handling for this
input shape for a buffer that is allocated before an attacker-controlled size/field is validated and
not released on the corresponding early-return/exception path. The two reproducers here are a good
starting corpus for that: replaying either one N times in a leak-checking build (e.g. built with
`-fsanitize=address` and `ASAN_OPTIONS=detect_leaks=1`, standalone driver, looped externally since
LeakSanitizer only reports at process exit) should point at the allocation site directly.

## Harness bound note

`fuzz_entry_read`'s per-call read budget (`kMaxChunkBytes=256KiB`, `kMaxTotalReadBytes=8MiB` per
input — see the harness header comment) does **not** prevent this: the leak is not proportional to
the bytes actually returned to the caller, so capping the requested read size does not cap it. This
was deliberately NOT patched into a guard/skip in the harness — SPEC 6b is explicit that crashes/OOMs
must not be masked, only genuinely non-terminating (hang) preconditions may be narrowly guarded, and
this is not a hang: each individual call returns normally.
