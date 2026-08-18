// mayhem/kat/genzim.cpp — ONE-TIME fixture generator, NOT part of mayhem/build.sh.
//
// libzim ships no committed .zim files (test/tools.cpp getDataFilePath() pulls real
// Wikipedia-derived fixtures from the openzim/zim-testing-suite GitHub release at test
// time, which is both a network dependency we don't want in an air-gapped re-run and
// gigabytes we don't want baked into every commit image). Per the net-new brief ("if
// absent, CREATE a tiny ZIM with libzim's own writer API and commit it"), this program
// was compiled and run ONCE (against a normal, non-sanitized meson build of this repo)
// to produce mayhem/fixtures/tiny.zim, which IS committed. mayhem/kat/kat_probe.cpp
// (built by build.sh, run by test.sh) opens that committed file and asserts exact
// values against it; mayhem/fuzz_archive/testsuite/ and mayhem/fuzz_entry_read/testsuite/
// ship copies of it (plus a truncated variant) as fuzzer starter seeds.
//
// Regenerate (from a libzim build tree with writer support):
//   g++ -std=c++17 -I include mayhem/kat/genzim.cpp -o /tmp/genzim -lzim
//   /tmp/genzim mayhem/fixtures/tiny.zim
//
// The archive has a deliberately small, fully-known layout so kat_probe.cpp can assert
// exact values: 3 user entries (2 plain items + 1 redirect), 1 metadata entry ("Title").
#include <zim/writer/creator.h>
#include <zim/writer/item.h>
#include <zim/writer/contentProvider.h>

#include <cstdio>
#include <memory>
#include <string>

namespace {

class GenItem : public zim::writer::Item {
  public:
    GenItem(std::string path, std::string mimetype, std::string title, std::string content)
      : path_(std::move(path)), mimetype_(std::move(mimetype)),
        title_(std::move(title)), content_(std::move(content))
    {}

    std::string getPath() const override { return path_; }
    std::string getTitle() const override { return title_; }
    std::string getMimeType() const override { return mimetype_; }

    std::unique_ptr<zim::writer::ContentProvider> getContentProvider() const override {
      return std::make_unique<zim::writer::StringProvider>(content_);
    }

    zim::writer::Hints getHints() const override {
      return zim::writer::Hints{{zim::writer::FRONT_ARTICLE, 1}};
    }

  private:
    std::string path_, mimetype_, title_, content_;
};

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::fprintf(stderr, "usage: %s <output.zim>\n", argv[0]);
    return 1;
  }

  zim::writer::Creator creator;
  creator.configClusterSize(1024);
  creator.startZimCreation(argv[1]);

  creator.addItem(std::make_shared<GenItem>(
      "hello", "text/html", "Hello World",
      "<html><body><h1>Hello World</h1></body></html>"));
  creator.addItem(std::make_shared<GenItem>(
      "data", "text/plain", "Plain Data",
      std::string(2000, 'A')));  // large-ish, compressible payload
  creator.addRedirection("alias", "Hello Alias", "hello");
  creator.addMetadata("Title", "tiny mayhem fixture");
  creator.setMainPath("hello");

  creator.finishZimCreation();
  std::printf("wrote %s\n", argv[1]);
  return 0;
}
