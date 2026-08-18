// mayhem/kat/kat_probe.cpp — direct known-answer probe against the REAL read API
// (zim::Archive/Entry/Item), run by mayhem/test.sh against the committed fixture
// mayhem/fixtures/tiny.zim (see mayhem/kat/genzim.cpp for how it was produced).
//
// WHY THIS EXISTS (SPEC 6.3 anti-reward-hacking / net-new brief 4): libzim's own gtest
// suite is driven one binary per TEST_F file, but that is still a plain dynamically
// linked executable under /mayhem — the exact shape verify-repo's sabotage shim can
// neuter via its constructor before main() (and therefore before a single gtest
// assertion) ever runs. Running the gtest binaries directly (test.sh does, parsing
// their OWN "[ PASSED ] N tests" line rather than trusting a wrapper's exit code)
// already catches that for the internal suite. This probe adds a SEPARATE, minimal,
// unconditional check of the exact public reading API our fuzz harnesses exercise
// (Archive -> Entry -> Item -> Blob), asserting exact values lifted from the fixture's
// own known construction (see genzim.cpp): a hardcoded entry count, a specific entry's
// title/mimetype/content, a redirect's target, and a metadata value. A neutered build
// (or a "fixed" library that quietly returns wrong/empty data) fails these comparisons;
// bash (running this binary) is unaffected by the shim either way, so the comparison
// itself can't be hidden.
//
// UNCONDITIONAL: a missing fixture is a hard FAILURE (never skipped) -- see main().
#include <zim/archive.h>
#include <zim/entry.h>
#include <zim/item.h>
#include <zim/blob.h>

#include <cstdio>
#include <exception>
#include <string>

namespace {

int g_failures = 0;

void expect(bool cond, const char* label) {
  if (cond) {
    std::printf("KAT PASS: %s\n", label);
  } else {
    std::printf("KAT FAIL: %s\n", label);
    ++g_failures;
  }
}

template <typename T>
void expect_eq(const T& got, const T& want, const char* label) {
  if (got == want) {
    std::printf("KAT PASS: %s\n", label);
  } else {
    std::printf("KAT FAIL: %s (got != want)\n", label);
    ++g_failures;
  }
}

}  // namespace

int main(int argc, char** argv) {
  const std::string fixture = (argc > 1) ? argv[1] : "mayhem/fixtures/tiny.zim";

  try {
    zim::Archive archive(fixture);

    // KAT 1: total user-entry count is exactly what genzim.cpp added (hello, data,
    // alias) -- the archive.getEntryCount() count of USER entries.
    std::printf("KAT_ENTRY_COUNT=%u\n", archive.getEntryCount());
    expect_eq<zim::entry_index_type>(archive.getEntryCount(), 3, "getEntryCount() == 3 user entries");

    // KAT 2: the "hello" item -- exact title/mimetype/content round-trip.
    {
      const auto entry = archive.getEntryByPath("hello");
      expect(!entry.isRedirect(), "hello is not a redirect");
      expect_eq<std::string>(entry.getTitle(), "Hello World", "hello title == 'Hello World'");
      const auto item = entry.getItem();
      expect_eq<std::string>(item.getMimetype(), "text/html", "hello mimetype == text/html");
      const std::string content(item.getData());
      expect_eq<std::string>(content, "<html><body><h1>Hello World</h1></body></html>",
                              "hello content == exact HTML string");
    }

    // KAT 3: the "data" item -- a larger, compressible payload; check exact size and
    // exact decompressed content (a real cluster/zstd round-trip, not just metadata).
    {
      const auto entry = archive.getEntryByPath("data");
      const auto item = entry.getItem();
      std::printf("KAT_DATA_SIZE=%llu\n", static_cast<unsigned long long>(item.getSize()));
      expect_eq<zim::size_type>(item.getSize(), 2000, "data item size == 2000 bytes");
      const std::string content(item.getData());
      expect_eq<std::string>(content, std::string(2000, 'A'), "data content == 2000x 'A'");
    }

    // KAT 4: the "alias" redirect resolves to "hello".
    {
      const auto entry = archive.getEntryByPath("alias");
      expect(entry.isRedirect(), "alias is a redirect");
      expect_eq<std::string>(entry.getRedirectEntry().getPath(), std::string("hello"),
                              "alias redirects to 'hello'");
    }

    // KAT 5: archive-level metadata round-trip.
    expect_eq<std::string>(archive.getMetadata("Title"), "tiny mayhem fixture",
                            "metadata Title == 'tiny mayhem fixture'");

  } catch (const std::exception& e) {
    std::printf("KAT FAIL: unexpected exception opening/reading fixture: %s\n", e.what());
    ++g_failures;
  }

  std::printf("KAT_SUMMARY: %d failure(s)\n", g_failures);
  return g_failures == 0 ? 0 : 1;
}
