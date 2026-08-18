// mayhem/harnesses/fuzz_entry_read.cpp — libFuzzer harness over zim::Archive PLUS
// actually decompressing and reading entry content, which drives the cluster/zstd
// (and, for older archives, LZMA) decompression path that fuzz_archive never touches.
//
// Same fd-based construction as fuzz_archive.cpp (memfd_create; see its header comment
// for the rationale — no filesystem path is ever used, so SPEC 6.2 item 13 does not
// apply). Read that file first; this one only adds the decompression walk.
//
// BOUNDING (SPEC 6b): a malformed dirent/cluster can claim an enormous item size, and
// zstd's own frame header can declare a huge decompressed size for a tiny compressed
// input (a classic decompression-bomb shape). We do NOT skip calling getData() based on
// the claimed size (that claim is attacker-controlled and skipping it would hide real
// bugs in size handling) -- instead we cap the TOTAL number of bytes read across the
// whole input via a running budget, and cap how many items we open. This bounds a
// single input's decompression work without masking crashes/OOMs: a genuine crash or
// ASan/UBSan abort while decompressing item #1 still fires before the budget check ever
// gets a say.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE  // memfd_create(2) declaration under a strict -std=c++17
#endif
#include <zim/archive.h>
#include <zim/entry.h>
#include <zim/item.h>
#include <zim/blob.h>

#include <cstddef>
#include <cstdint>
#include <exception>

#include <sys/mman.h>
#include <unistd.h>

namespace {
constexpr size_t kMaxInputBytes = 32u * 1024 * 1024;
constexpr zim::entry_index_type kMaxEntriesWalked = 200;
constexpr zim::entry_index_type kMaxItemsRead = 64;
// Total decompressed bytes we are willing to pull out of ONE input across all items.
// This is a productivity bound, not a correctness one -- see header comment.
constexpr zim::size_type kMaxTotalReadBytes = 8u * 1024 * 1024;
// Per-item read chunk (via Item::getData(offset, size)) -- bounds a single getData()
// call even when an item claims to be far larger than our remaining budget.
constexpr zim::size_type kMaxChunkBytes = 256u * 1024;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0 || size > kMaxInputBytes) {
    return 0;
  }

  int fd = memfd_create("fuzz_entry_read_input", 0);
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
    close(fd);
    fd = -1;

    const zim::entry_index_type total = archive.getAllEntryCount();
    const zim::entry_index_type n = total < kMaxEntriesWalked ? total : kMaxEntriesWalked;

    zim::entry_index_type itemsRead = 0;
    zim::size_type totalBytesRead = 0;

    for (zim::entry_index_type i = 0; i < n && itemsRead < kMaxItemsRead
                                       && totalBytesRead < kMaxTotalReadBytes; ++i) {
      try {
        const zim::Entry entry = archive.getEntryByPath(i);
        if (entry.isRedirect()) {
          continue;
        }
        const zim::Item item = entry.getItem();
        (void)item.getMimetype();
        ++itemsRead;

        // Read in bounded chunks so one oversized/lying item can only ever consume
        // up to kMaxChunkBytes per call; the outer budget stops the whole loop once
        // kMaxTotalReadBytes has been decompressed across all items in this input.
        zim::size_type offset = 0;
        const zim::size_type declaredSize = item.getSize();
        while (offset < declaredSize && totalBytesRead < kMaxTotalReadBytes) {
          const zim::size_type remainingBudget = kMaxTotalReadBytes - totalBytesRead;
          const zim::size_type chunk = kMaxChunkBytes < remainingBudget ? kMaxChunkBytes : remainingBudget;
          const zim::Blob blob = item.getData(offset, chunk);
          if (blob.size() == 0) {
            break;  // no more data than what we already have
          }
          totalBytesRead += blob.size();
          offset += blob.size();
        }
      } catch (const std::exception&) {
        continue;
      }
    }
  } catch (const std::exception&) {
    // Expected outcome for a malformed/truncated ZIM or corrupt compressed cluster.
    if (fd >= 0) {
      close(fd);
    }
  }

  return 0;
}
