// Regression tests for PcapFileCapture handle ownership.
#include <type_traits>

#include <catch2/catch_test_macros.hpp>

#include "PcapFileCapture.hpp"

using netsentinel::PcapFileCapture;

static_assert(!std::is_copy_constructible<PcapFileCapture>::value, "capture must not be copyable");
static_assert(!std::is_copy_assignable<PcapFileCapture>::value, "capture must not be copy-assignable");

#ifndef NS_SOURCE_DIR
#error "NS_SOURCE_DIR must be defined by CMake"
#endif

TEST_CASE("Reopening a capture releases the first handle and reads from the start", "[capture][capture-ownership]") {
    const std::string path = std::string(NS_SOURCE_DIR) + "/data/sample.pcap";
    PcapFileCapture cap;
    REQUIRE(cap.open(path));
    REQUIRE(cap.next().has_value());
    // Second open on the same object: under ASan/LSan the old handle must not leak.
    REQUIRE(cap.open(path));
    int n = 0;
    while (cap.next()) ++n;
    REQUIRE(n == 717);          // sample.pcap has 717 records (original summary: packets read 717)
    REQUIRE_FALSE(cap.hadError());
}

TEST_CASE("Original (on-wire) length and link type are reported", "[capture][on-wire-length]") {
    const std::string path = std::string(NS_SOURCE_DIR) + "/data/sample.pcap";
    PcapFileCapture cap;
    REQUIRE(cap.linkType() == -1);
    REQUIRE(cap.open(path));
    auto v = cap.next();
    REQUIRE(v.has_value());
    REQUIRE(v->original_length == v->length); // sample.pcap is not truncated
    REQUIRE(cap.linkType() == 1);             // DLT_EN10MB
}

TEST_CASE("Snaplen-truncated capture: view length is the captured length, not the on-wire length (mutant M25)",
          "[capture][captured-length]") {
    // tests/data/audit/snaplen64.pcap: 1,514-byte frames saved with snaplen 64. Every bounds check in
    // FeatureExtractor uses RawPacketView::length, so length must be caplen (64); trusting the on-wire
    // length (1514) would let the parser read past the captured bytes.
    const std::string path = std::string(NS_SOURCE_DIR) + "/tests/data/audit/snaplen64.pcap";
    PcapFileCapture cap;
    REQUIRE(cap.open(path));
    int n = 0;
    while (auto v = cap.next()) {
        REQUIRE(v->length == 64);
        REQUIRE(v->original_length == 1514);
        ++n;
    }
    REQUIRE(n == 600);
    REQUIRE_FALSE(cap.hadError());
}
