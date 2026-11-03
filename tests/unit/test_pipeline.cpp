// Regression tests for Pipeline's time and window policy, driven by synthetic
// timestamps (no PCAP needed). Each test names the rule it pins.
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "Pipeline.hpp"

using namespace netsentinel;

namespace {

PacketFeature pkt(double ts, int ip = 1, uint16_t port = 80) {
    PacketFeature f;
    f.timestamp_sec = ts;
    f.packet_size_bytes = 100;
    f.protocol = 6;
    f.dst_ip = "10.0.0." + std::to_string(ip);
    f.dst_port = port;
    f.has_ports = true;
    return f;
}

struct Run {
    std::vector<WindowResult> windows;
    Pipeline pipe;
    explicit Run(PipelineConfig c = {}) : pipe(c, [this](const WindowResult& r) { windows.push_back(r); }) {}
    void add(double ts) { pipe.onPacket(ts, pkt(ts), SkipReason::None); }
    void addSkipped(double ts, SkipReason r) { pipe.onPacket(ts, std::nullopt, r); }
};

} // namespace

TEST_CASE("Out-of-order packet inside the open window is processed", "[pipeline][time-policy]") {
    Run r;
    r.add(1000.0); r.add(1003.0); r.add(1001.0); r.add(1006.0);
    r.pipe.finish();
    REQUIRE(r.pipe.counters().lateDropped == 0);
    REQUIRE(r.windows.at(0).features.packet_count == 3);
}

TEST_CASE("Packet earlier than the open window's start is dropped and counted", "[pipeline][time-policy]") {
    Run r;
    r.add(1000.0); r.add(1006.0); r.add(1004.0); r.add(1007.0);
    r.pipe.finish();
    REQUIRE(r.pipe.counters().lateDropped == 1);
    REQUIRE(r.windows.at(0).features.packet_count == 1);
    REQUIRE(r.windows.at(1).features.packet_count == 2);
    REQUIRE(r.windows.at(1).features.late_dropped == 1);
}

TEST_CASE("Isolated far-future packet is quarantined by one-packet look-ahead", "[pipeline][time-policy]") {
    Run r;
    r.add(1000.0); r.add(1001.0); r.add(4600.0); r.add(1002.0); r.add(1006.0);
    r.pipe.finish();
    REQUIRE(r.pipe.counters().quarantined == 1);
    REQUIRE(r.pipe.counters().lateDropped == 0);
    REQUIRE(r.windows.size() == 2);
    REQUIRE(r.windows.at(0).features.packet_count == 3);
}

TEST_CASE("Far-future packet at end of file is quarantined", "[pipeline][time-policy]") {
    Run r;
    r.add(1000.0); r.add(1001.0); r.add(9999.0);
    r.pipe.finish();
    REQUIRE(r.pipe.counters().quarantined == 1);
    REQUIRE(r.windows.size() == 1);
    REQUIRE(r.windows.at(0).status == WindowStatus::Partial);
}

TEST_CASE("Two consecutive far-future packets are treated as a real jump (documented limitation)", "[pipeline][time-policy]") {
    Run r;
    r.add(1000.0); r.add(2000.0); r.add(2000.5); r.add(1001.0);
    r.pipe.finish();
    REQUIRE(r.pipe.counters().quarantined == 0);
    REQUIRE(r.pipe.counters().gapCaps == 1);
    REQUIRE(r.pipe.counters().lateDropped == 1); // 1001.0 now belongs to the past
}

TEST_CASE("Gap within the cap emits every empty window; longer gap emits 12 then skips", "[pipeline][time-policy]") {
    SECTION("60 s gap: all 11 empty windows emitted, no cap") {
        Run r;
        r.add(1000.0); r.add(1060.0); r.add(1061.0);
        r.pipe.finish();
        REQUIRE(r.pipe.counters().gapCaps == 0);
        REQUIRE(r.pipe.counters().windowsIdle == 11);
    }
    SECTION("timestamp 0 followed by real epoch time finishes in O(1) windows") {
        Run r;
        r.add(0.0); r.add(1.7e9); r.add(1.7e9 + 1.0);
        r.pipe.finish();
        REQUIRE(r.pipe.counters().gapCaps == 1);
        REQUIRE(r.pipe.counters().windowsIdle == 12);
        REQUIRE(r.windows.size() == 14); // window 0, 12 idle, partial
        REQUIRE(r.windows.back().features.window_start_sec <= 1.7e9 + 1.0);
        REQUIRE(r.windows.back().features.window_end_sec > 1.7e9 + 1.0);
    }
}

TEST_CASE("Idle and no-parsed windows are neither scored nor learned", "[pipeline][idle-window]") {
    Run r;
    for (int i = 0; i < 25; ++i) r.add(1000.0 + 5.0 * i);
    r.addSkipped(1125.5, SkipReason::Ipv6);          // window 25: only IPv6
    r.add(1135.0);                                    // window 26 idle? no: 1130-1135 idle, 1135 starts window 27
    r.add(1141.0);
    r.pipe.finish();
    REQUIRE(r.windows.at(25).status == WindowStatus::NoParsedTraffic);
    REQUIRE(r.windows.at(25).features.skipped_ipv6 == 1);
    REQUIRE(r.windows.at(26).status == WindowStatus::Idle);
    REQUIRE(r.windows.at(25).action == BaselineAction::NotLearned);
    REQUIRE(r.windows.at(26).action == BaselineAction::NotLearned);
    REQUIRE(r.pipe.counters().windowsScored == 26);  // windows 0..24 and 27
    REQUIRE(r.pipe.counters().alerts == 0);
}

TEST_CASE("Final window is partial: neither scored nor learned", "[pipeline][partial-window]") {
    Run r;
    for (int i = 0; i < 30; ++i) r.add(1000.0 + 5.0 * i);
    r.pipe.finish();
    REQUIRE(r.windows.back().status == WindowStatus::Partial);
    REQUIRE(r.windows.back().action == BaselineAction::NotLearned);
    REQUIRE(r.pipe.counters().windowsScored == 29);
}

TEST_CASE("Fractional timestamps keep the grid exact", "[pipeline][fractional-time]") {
    Run r;
    r.add(1000.5); r.add(1005.2); r.add(1005.6);
    r.pipe.finish();
    REQUIRE(r.windows.at(0).features.packet_count == 2); // [1000.5, 1005.5)
    REQUIRE(r.windows.at(0).features.window_start_sec == 1000.5);
}

TEST_CASE("Skipped packets advance the clock", "[pipeline][time-advance]") {
    Run r;
    r.add(1000.0);
    r.addSkipped(1007.0, SkipReason::OtherEthertype); // closes window 0 even though not parsed
    r.pipe.finish();
    REQUIRE(r.windows.size() == 2);
    REQUIRE(r.windows.at(0).status == WindowStatus::Scored);
    REQUIRE(r.windows.at(1).features.skipped_other_ethertype == 1);
}
