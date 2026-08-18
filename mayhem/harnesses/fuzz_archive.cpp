// mayhem/harnesses/fuzz_archive.cpp — libFuzzer harness over zim::Archive.
//
// Fuzzed surface: opening an UNTRUSTED ZIM archive (header, mimetype list, url/title
// pointer lists, the directory-entry table) and walking a bounded number of entries
// (path, title, redirect resolution, item mimetype) — the "is this a well-formed
// ZIM container" surface, without decompressing cluster content (see fuzz_entry_read
// for that).
//
// FILE-PATH PROBLEM (SPEC 6.2 item 13 / net-new brief 3): zim::Archive is normally
// constructed from a filename and mmaps it. Mayhem mounts the image read-only and
// runs the target from its own cwd, so writing the fuzz bytes to any path under the
// image or a relative path would fail on every input. Route taken: libzim exposes an
// fd-based constructor (`Archive(int fd)`, include/zim/archive.h) — we materialize the
// input in an anonymous, unlinked, RAM-backed file via memfd_create(2) (never touches
// a filesystem path at all, so /dev/shm is not even needed) and open THAT. The fd is
// used by libzim "only at Archive creation" per its own docs, so it is safe to close
// immediately after the constructor returns (success or throw) — this also prevents
// an fd leak across the many thousands of iterations in one fuzzing process.
//
// BOUNDING (SPEC 6b): a malformed header can declare an enormous entry count. We cap
// the number of entries walked per input; the per-entry try/catch means one bad dirent
// can't stop iteration over the rest. zim::Archive() and friends throw on malformed
// input (zim::ZimFileFormatError, std::out_of_range, ...) as the EXPECTED outcome for
// a mostly-invalid fuzz corpus — caught via std::exception, never a bare `...` (so a
// real sanitizer abort still surfaces as a crash, not a "handled" exception).
#ifndef _GNU_SOURCE
#define _GNU_SOURCE  // memfd_create(2) declaration under a strict -std=c++17
#endif
#include <zim/archive.h>
#include <zim/entry.h>
#include <zim/item.h>

#include <cstddef>
#include <cstdint>
#include <exception>

#include <sys/mman.h>
#include <unistd.h>

namespace {
constexpr size_t kMaxInputBytes = 32u * 1024 * 1024;   // ignore absurdly large inputs
constexpr zim::entry_index_type kMaxEntriesWalked = 500;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0 || size > kMaxInputBytes) {
    return 0;
  }

  int fd = memfd_create("fuzz_archive_input", 0);
  if (fd < 0) {
    return 0;
  }

  size_t written = 0;
  while (written < size) {
    ssize_t n = write(fd, data + written, size - written);
    if (n <= 0) {
      close(fd);
      return 0;
    }
    written += static_cast<size_t>(n);
  }
  lseek(fd, 0, SEEK_SET);

  try {
    zim::Archive archive(fd);
    close(fd);  // fd is only needed at construction time (see header comment)
    fd = -1;    // so the catch below can't double-close it if a later call throws

    const zim::entry_index_type total = archive.getAllEntryCount();
    const zim::entry_index_type n = total < kMaxEntriesWalked ? total : kMaxEntriesWalked;

    for (zim::entry_index_type i = 0; i < n; ++i) {
      try {
        const zim::Entry entry = archive.getEntryByPath(i);
        (void)entry.getTitle();
        (void)entry.getPath();
        if (entry.isRedirect()) {
          (void)entry.getRedirectEntry().getPath();
        } else {
          const zim::Item item = entry.getItem();
          (void)item.getMimetype();
          (void)item.getSize();
        }
      } catch (const std::exception&) {
        // A single malformed dirent must not stop the walk over the rest.
        continue;
      }
    }

    // A couple of archive-wide accessors that walk separate index structures
    // (mimetype list / metadata keys) rather than the dirent table above.
    try {
      (void)archive.getMetadataKeys();
      (void)archive.getUuid();
      (void)archive.getFilesize();
    } catch (const std::exception&) {
    }
  } catch (const std::exception&) {
    // Expected outcome for a malformed/truncated ZIM: zim::ZimFileFormatError etc.
    if (fd >= 0) {
      close(fd);
    }
  }

  return 0;
}
