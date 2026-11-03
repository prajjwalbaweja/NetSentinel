// Regression tests for FeatureExtractor: link layers, on-wire length, fragments, truncated headers,
// exact-size buffers.
// Every frame is built in an exactly-sized std::vector so that, under NS_SANITIZE=ON, any read
// past the captured bytes is reported by AddressSanitizer (this is what makes the bounds-check
// mutants A09, A10, A12 detectable; the audit found them surviving the original suite).
#include <cstdint>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "FeatureExtractor.hpp"

using namespace netsentinel;

namespace {

using Bytes = std::vector<uint8_t>;

void put16(Bytes& b, uint16_t v) { b.push_back(uint8_t(v >> 8)); b.push_back(uint8_t(v & 0xFF)); }

Bytes ipv4Header(uint8_t proto, uint16_t flagsFrag = 0, uint8_t versionIhl = 0x45, uint16_t totalLen = 40) {
    Bytes h;
    h.push_back(versionIhl); h.push_back(0); put16(h, totalLen); put16(h, 0); put16(h, flagsFrag);
    h.push_back(64); h.push_back(proto); put16(h, 0);
    for (uint8_t x : {192, 168, 1, 50}) h.push_back(x);
    for (uint8_t x : {10, 0, 0, 7}) h.push_back(x);
    return h;
}

Bytes tcpHeader(uint16_t sport, uint16_t dport) {
    Bytes t; put16(t, sport); put16(t, dport);
    for (int i = 0; i < 8; ++i) t.push_back(0);
    put16(t, (5 << 12) | 0x10); put16(t, 8192); put16(t, 0); put16(t, 0);
    return t;
}

Bytes ethernet(uint16_t ethertype, const Bytes& payload, int vlanTags = 0) {
    Bytes f(12, 0xAA);
    for (int i = 0; i < vlanTags; ++i) { put16(f, i == 0 && vlanTags == 2 ? 0x88A8 : 0x8100); put16(f, 10); }
    put16(f, ethertype);
    f.insert(f.end(), payload.begin(), payload.end());
    return Bytes(f.begin(), f.end()); // exact capacity: ASan sees any read past size()
}

Bytes cat(Bytes a, const Bytes& b) { a.insert(a.end(), b.begin(), b.end()); return Bytes(a.begin(), a.end()); }

RawPacketView view(const Bytes& b, std::size_t orig = 0) {
    RawPacketView v; v.data = b.data(); v.length = b.size(); v.original_length = orig ? orig : b.size();
    v.capture_timestamp_sec = 1000.0; return v;
}

const Bytes TCP443 = cat(ipv4Header(6), tcpHeader(50000, 443));

} // namespace

TEST_CASE("Plain Ethernet IPv4/TCP is parsed with ports", "[extractor]") {
    FeatureExtractor fx;
    const Bytes f = ethernet(0x0800, TCP443);
    auto p = fx.extract(view(f));
    REQUIRE(p.has_value());
    REQUIRE(p->dst_ip == "10.0.0.7");
    REQUIRE(p->dst_port == 443);
    REQUIRE(p->has_ports);
    REQUIRE(p->packet_size_bytes == f.size());
}

TEST_CASE("802.1Q and QinQ tagged frames are parsed", "[extractor][link-layers]") {
    FeatureExtractor fx;
    for (int tags : {1, 2}) {
        const Bytes f = ethernet(0x0800, TCP443, tags);
        auto p = fx.extract(view(f));
        REQUIRE(p.has_value());
        REQUIRE(p->dst_port == 443);
    }
    // A tag header cut short is a truncated link header, never an out-of-bounds read.
    Bytes cut0(12, 0xAA); put16(cut0, 0x8100); cut0.push_back(0);
    const Bytes cut(cut0.begin(), cut0.end());
    REQUIRE_FALSE(fx.extract(view(cut)).has_value());
    REQUIRE(fx.lastSkipReason() == SkipReason::TruncatedLinkHeader);
}

TEST_CASE("Linux cooked capture (SLL) is parsed when the link type says so", "[extractor][link-layers]") {
    FeatureExtractor fx(FeatureExtractor::LINKTYPE_LINUX_SLL);
    Bytes f; put16(f, 0); put16(f, 1); put16(f, 6); for (int i = 0; i < 8; ++i) f.push_back(0); put16(f, 0x0800);
    f = cat(f, TCP443); // cat() returns an exactly sized copy
    auto p = fx.extract(view(f));
    REQUIRE(p.has_value());
    REQUIRE(p->dst_port == 443);
    REQUIRE(FeatureExtractor::isSupportedLinkType(113));
    REQUIRE_FALSE(FeatureExtractor::isSupportedLinkType(101));
}

TEST_CASE("Packet size is the on-wire length, not the snaplen", "[extractor][on-wire-length]") {
    FeatureExtractor fx;
    const Bytes f = ethernet(0x0800, TCP443);
    auto p = fx.extract(view(f, 1514));
    REQUIRE(p.has_value());
    REQUIRE(p->packet_size_bytes == 1514);
}

TEST_CASE("Non-first IP fragments carry no ports", "[extractor][fragments]") {
    FeatureExtractor fx;
    const Bytes f = ethernet(0x0800, cat(ipv4Header(17, 185), Bytes{0x03, 0xE8, 0x07, 0xD0, 0, 0, 0, 0}));
    auto p = fx.extract(view(f));
    REQUIRE(p.has_value());          // still an IPv4 packet: counted, destination IP kept
    REQUIRE_FALSE(p->has_ports);
    // First fragment (MF set, offset 0) still has its header, so ports are read.
    const Bytes first = ethernet(0x0800, cat(ipv4Header(6, 0x2000), tcpHeader(1, 22)));
    auto q = fx.extract(view(first));
    REQUIRE(q.has_value());
    REQUIRE(q->has_ports);
    REQUIRE(q->dst_port == 22);
}

TEST_CASE("Truncated transport header: ports read with 4 bytes, none with fewer", "[extractor][truncated-transport]") {
    FeatureExtractor fx;
    const Bytes four = ethernet(0x0800, cat(ipv4Header(6), Bytes{0xC3, 0x50, 0x01, 0xBB}));
    auto p = fx.extract(view(four, 1514));
    REQUIRE(p.has_value());
    REQUIRE(p->has_ports);
    REQUIRE(p->dst_port == 443);
    const Bytes three = ethernet(0x0800, cat(ipv4Header(6), Bytes{0xC3, 0x50, 0x01}));
    auto q = fx.extract(view(three, 1514));
    REQUIRE(q.has_value());
    REQUIRE_FALSE(q->has_ports);
}

TEST_CASE("Malformed IPv4 headers are rejected without reading past the buffer", "[extractor][exact-buffers]") {
    FeatureExtractor fx;
    // Shorter than a minimal IPv4 header (14 + 19 bytes).
    Bytes shortIp = ethernet(0x0800, Bytes(19, 0x45));
    REQUIRE_FALSE(fx.extract(view(shortIp)).has_value());
    REQUIRE(fx.lastSkipReason() == SkipReason::MalformedIpv4);
    // Only the 14-byte Ethernet header present.
    Bytes ethOnly = ethernet(0x0800, Bytes{});
    REQUIRE_FALSE(fx.extract(view(ethOnly)).has_value());
    // IHL < 5.
    Bytes badIhl = ethernet(0x0800, cat(ipv4Header(6, 0, 0x44), tcpHeader(1, 2)));
    REQUIRE_FALSE(fx.extract(view(badIhl)).has_value());
    // IHL = 15 (60-byte header) but only 20 header bytes captured.
    Bytes bigIhl = ethernet(0x0800, ipv4Header(6, 0, 0x4F));
    REQUIRE_FALSE(fx.extract(view(bigIhl)).has_value());
    // Version 6 nibble inside an IPv4 ethertype.
    Bytes badVer = ethernet(0x0800, cat(ipv4Header(6, 0, 0x65), tcpHeader(1, 2)));
    REQUIRE_FALSE(fx.extract(view(badVer)).has_value());
    REQUIRE(fx.lastSkipReason() == SkipReason::MalformedIpv4);
    // Shorter than an Ethernet header.
    Bytes tiny{1, 2, 3, 4, 5};
    REQUIRE_FALSE(fx.extract(view(tiny)).has_value());
    REQUIRE(fx.lastSkipReason() == SkipReason::TruncatedLinkHeader);
}

TEST_CASE("IPv6 and other ethertypes are skipped with distinct reasons", "[extractor]") {
    FeatureExtractor fx;
    Bytes v6 = ethernet(0x86DD, Bytes(40, 0));
    REQUIRE_FALSE(fx.extract(view(v6)).has_value());
    REQUIRE(fx.lastSkipReason() == SkipReason::Ipv6);
    Bytes arp = ethernet(0x0806, Bytes(28, 0));
    REQUIRE_FALSE(fx.extract(view(arp)).has_value());
    REQUIRE(fx.lastSkipReason() == SkipReason::OtherEthertype);
    REQUIRE(fx.extract(view(ethernet(0x0800, TCP443))).has_value());
    REQUIRE(fx.lastSkipReason() == SkipReason::None);
}
