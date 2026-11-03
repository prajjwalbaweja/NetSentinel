// Baseline policy tests: cumulative baseline unchanged, gated baseline with 60-window recovery,
// SD floor in the gated baseline only, frozen-threshold comparator.
#include <cmath>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "Pipeline.hpp"

using namespace netsentinel;

namespace {

// One window per call: n packets to `ips` distinct destinations, spread inside window i.
struct Run {
    std::vector<WindowResult> w;
    Pipeline pipe;
    int i = 0;
    explicit Run(PipelineConfig c) : pipe(c, [this](const WindowResult& r) { w.push_back(r); }) {}
    void window(int n) {
        for (int k = 0; k < n; ++k) {
            PacketFeature f;
            f.timestamp_sec = 1000.0 + 5.0 * i + k * 5.0 / n;
            f.packet_size_bytes = 100; f.protocol = 6; f.dst_ip = "10.0.0.1"; f.dst_port = 80; f.has_ports = true;
            pipe.onPacket(f.timestamp_sec, f, SkipReason::None);
        }
        ++i;
    }
    void benign(int count) { for (int j = 0; j < count; ++j) window(18 + (i % 5)); } // 18..22, non-constant
};

PipelineConfig cfg(BaselinePolicy p, bool floor = false, int recovery = 60) {
    PipelineConfig c; c.policy = p; c.sdFloorEnabled = floor; c.recoveryWindows = recovery; return c;
}

} // namespace

TEST_CASE("Cumulative baseline learns every scored window, including alerting ones (unchanged original policy)", "[policy][cumulative]") {
    Run r(cfg(BaselinePolicy::Cumulative));
    r.benign(30); r.window(200); r.benign(2);
    r.pipe.finish();
    REQUIRE(r.w.at(30).alert.has_value());
    REQUIRE(r.w.at(30).action == BaselineAction::Updated);
}

TEST_CASE("Gated baseline skips alerting windows and resets on a normal window", "[policy][gated]") {
    Run r(cfg(BaselinePolicy::Gated));
    r.benign(30); r.window(200); r.window(200); r.benign(2);
    r.pipe.finish();
    REQUIRE(r.w.at(30).action == BaselineAction::Gated);
    REQUIRE(r.w.at(30).consecutiveAlerts == 1);
    REQUIRE(r.w.at(31).action == BaselineAction::Gated);
    REQUIRE(r.w.at(31).consecutiveAlerts == 2);
    REQUIRE(r.w.at(32).action == BaselineAction::Updated); // back to normal: not alerting, learned
    REQUIRE(r.w.at(32).consecutiveAlerts == 0);
}

TEST_CASE("Gated baseline keeps a sustained attack visible for 60 windows, then resumes learning", "[policy][gated][recovery]") {
    Run r(cfg(BaselinePolicy::Gated));
    r.benign(30);
    for (int j = 0; j < 80; ++j) r.window(200);
    r.window(20);
    r.pipe.finish();
    for (int j = 30; j < 90; ++j) {
        REQUIRE(r.w.at(j).alert.has_value());
        REQUIRE(r.w.at(j).action == BaselineAction::Gated);
    }
    REQUIRE(r.w.at(90).action == BaselineAction::ForcedUpdate); // 61st consecutive alerting window
    REQUIRE(r.w.at(90).consecutiveAlerts == 61);
}

TEST_CASE("Cumulative baseline absorbs the same sustained attack much sooner than the gated baseline", "[policy][cumulative][recovery]") {
    Run cumulative(cfg(BaselinePolicy::Cumulative)), gated(cfg(BaselinePolicy::Gated));
    for (Run* r : {&cumulative, &gated}) { r->benign(30); for (int j = 0; j < 80; ++j) r->window(200); r->window(20); r->pipe.finish(); }
    int cumulativeAlerts = 0, gatedAlerts = 0;
    for (int j = 30; j < 110; ++j) { cumulativeAlerts += cumulative.w.at(j).alert ? 1 : 0; gatedAlerts += gated.w.at(j).alert ? 1 : 0; }
    REQUIRE(cumulativeAlerts < 10);
    REQUIRE(gatedAlerts >= 60);
}

TEST_CASE("Gated-baseline recovery is configurable (12-window sensitivity run)", "[policy][gated][recovery]") {
    Run r(cfg(BaselinePolicy::Gated, false, 12));
    r.benign(30);
    for (int j = 0; j < 20; ++j) r.window(200);
    r.window(20);
    r.pipe.finish();
    REQUIRE(r.w.at(41).action == BaselineAction::Gated);
    REQUIRE(r.w.at(42).action == BaselineAction::ForcedUpdate);
}

TEST_CASE("SD floor makes a constant baseline scorable in the gated baseline; the cumulative baseline stays inconclusive", "[policy][sd-floor]") {
    for (bool floor : {false, true}) {
        Run r(cfg(BaselinePolicy::Gated, floor));
        for (int j = 0; j < 30; ++j) r.window(20); // perfectly constant
        r.window(40);
        r.window(20);
        r.pipe.finish();
        if (floor) {
            REQUIRE(r.w.at(30).zState[0] == ZState::Value);
            REQUIRE(std::fabs(r.w.at(30).z[0] - 40.0) < 1e-9); // (40 - 20) / max(0, 0.5)
            REQUIRE(r.w.at(30).alert.has_value());
        } else {
            REQUIRE(r.w.at(30).zState[0] == ZState::NotAvailable);
            REQUIRE_FALSE(r.w.at(30).alert.has_value());
        }
    }
    Run cumulative(cfg(BaselinePolicy::Cumulative, true)); // floor flag is ignored for the cumulative baseline inside the pipeline
    for (int j = 0; j < 30; ++j) cumulative.window(20);
    cumulative.window(40); cumulative.window(20); cumulative.pipe.finish();
    REQUIRE(cumulative.w.at(30).zState[0] == ZState::NotAvailable);
}

TEST_CASE("Frozen-threshold comparator learns warm-up windows only", "[policy][frozen]") {
    Run r(cfg(BaselinePolicy::Frozen));
    r.benign(25); r.window(200); r.benign(3);
    r.pipe.finish();
    for (int j = 0; j < 20; ++j) REQUIRE(r.w.at(j).action == BaselineAction::Updated);
    for (int j = 20; j < 28; ++j) REQUIRE(r.w.at(j).action == BaselineAction::Frozen);
    REQUIRE(r.w.at(25).alert.has_value());
}
