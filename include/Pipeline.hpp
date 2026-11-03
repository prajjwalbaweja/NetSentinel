#pragma once

#include <array>
#include <functional>
#include <optional>

#include "AlertEvent.hpp"
#include "AnomalyScorer.hpp"
#include "FeatureExtractor.hpp"
#include "StatEngine.hpp"
#include "WindowAggregator.hpp"

namespace netsentinel {

// Pipeline owns the per-packet time policy, the window grid, the four baselines and the scorer.
// It replaces the loop that used to live in main.cpp, so the behaviour can be unit-tested
// without a PCAP file. main.cpp only reads packets, calls onPacket()/finish() and prints.
//
// Time policy:
//  * Every packet with a timestamp advances the window clock, parsed or not.
//  * Late packet: timestamp earlier than the start of the currently open window -> dropped and
//    counted. An out-of-order packet still inside the open window is processed normally.
//  * Far-future packet: timestamp more than gapCapSec after the latest accepted timestamp. It is
//    held for one packet (look-ahead). If the next packet is back within gapCapSec of the latest
//    accepted timestamp, the held packet was an isolated glitch and is quarantined (dropped and
//    counted). Otherwise the jump is treated as real time and both packets are processed.
//    A held packet at end of file is quarantined. Limitation: two or more consecutive far-future
//    packets are always treated as a real jump.
//  * Idle gap: at most gapCapSec worth of empty windows (12 at 5 s) is emitted; the rest of the
//    gap is skipped in one step and counted as a gap-cap event (a bad first timestamp no longer creates hundreds of millions of windows).
//
// Window policy:
//  * A window with no packets at all (Idle) or with packets but none parsed (NoParsedTraffic) is
//    reported, but neither scored nor learned.
//  * The window still open at end of file (Partial) is reported, but neither scored nor learned.
//  * Every other window is scored against the pre-existing baseline, then learned (score-then-update).
enum class WindowStatus { Scored, Idle, NoParsedTraffic, Partial };
const char* windowStatusName(WindowStatus s);

enum class BaselineAction {
    Updated,       // window folded into the baseline
    NotLearned,    // idle / no parsed traffic / partial: never learned
    Gated,         // gated baseline: alerting window kept out of the baseline
    ForcedUpdate,  // gated baseline: alerting window learned because the recovery limit was reached
    Frozen,        // frozen-threshold comparator: baseline no longer updated after warm-up
};

// Baseline update policies compared in the evaluation (command-line value in brackets).
//  Cumulative  cumulative baseline (cumulative): original Welford baseline, every scored window is learned
//              (unchanged from the original prototype).
//  Gated       gated baseline (gated): cumulative Welford baseline in which a window that raises an alert is NOT learned; after
//              `recoveryWindows` consecutive alerting windows have been gated, further consecutive
//              alerting windows are learned again (forced update), so a sustained legitimate change cannot
//              lock the baseline out forever. Any non-alerting scored window resets the count.
//              Idle / no-parsed / partial windows neither count nor reset (they are not scored).
//  Frozen      fixed-threshold comparator (frozen): the baseline learns the warm-up windows only and is then
//              frozen, i.e. thresholds mean +/- T*sigma computed from warm-up data are used for the rest of the run.
enum class BaselinePolicy { Cumulative, Gated, Frozen };
const char* baselinePolicyName(BaselinePolicy p);
const char* baselineActionName(BaselineAction a);

constexpr int FEATURE_COUNT = 4;
extern const std::array<const char*, FEATURE_COUNT> FEATURE_NAMES;

enum class ZState { NotScored, Warmup, NotAvailable, Value };

struct WindowResult {
    int index = 0;
    WindowFeatures features;
    WindowStatus status = WindowStatus::Scored;
    std::array<ZState, FEATURE_COUNT> zState{};
    std::array<double, FEATURE_COUNT> z{};
    std::optional<AlertEvent> alert;
    BaselineAction action = BaselineAction::NotLearned;
    int consecutiveAlerts = 0; // gated-baseline state after this window (0 for the cumulative baseline)
};

struct PipelineConfig {
    double gapCapSec = 60.0;                                  // idle-gap cap / far-future threshold
    double threshold = IAnomalyScorer::DEFAULT_Z_THRESHOLD;   // |z| > threshold triggers
    BaselinePolicy policy = BaselinePolicy::Cumulative;
    int recoveryWindows = 60;                                 // gated baseline: learning resumes after N consecutive alerts
    bool sdFloorEnabled = false;                              // SD floor: gated baseline only
    // Per-feature minimum standard deviation (SD floor), order = FEATURE_NAMES. Defaults chosen by the
    // synthetic floor experiment (tools/experiments/floor_sweep.py, docs/evidence/floor_sweep/floor_sweep.md).
    std::array<double, 4> sdFloor = DEFAULT_SD_FLOOR;
    static constexpr std::array<double, 4> DEFAULT_SD_FLOOR = {0.5, 2.0, 0.5, 0.5};
};

struct PipelineCounters {
    long packetsRead = 0;
    long packetsParsed = 0;
    long skippedTruncatedLink = 0;
    long skippedIpv6 = 0;
    long skippedOtherEthertype = 0;
    long skippedMalformedIpv4 = 0;
    long lateDropped = 0;
    long quarantined = 0;
    long gapCaps = 0;
    long idleWindowsSuppressed = 0;
    long windowsEmitted = 0;
    long windowsScored = 0;
    long windowsIdle = 0;
    long windowsNoParsedTraffic = 0;
    long windowsPartial = 0;
    long alerts = 0;

    long packetsSkipped() const {
        return skippedTruncatedLink + skippedIpv6 + skippedOtherEthertype + skippedMalformedIpv4;
    }
};

class Pipeline {
public:
    using Sink = std::function<void(const WindowResult&)>;

    Pipeline(PipelineConfig config, Sink sink);

    // Call once per packet read from the capture, in file order. `feature` is empty when the
    // extractor skipped the packet; `reason` then says why.
    void onPacket(double timestampSec, const std::optional<PacketFeature>& feature, SkipReason reason);

    // Call once at end of capture (clean EOF or read error).
    void finish();

    const PipelineCounters& counters() const { return counters_; }

private:
    struct Packet {
        double ts = 0.0;
        std::optional<PacketFeature> feature;
        SkipReason reason = SkipReason::None;
    };

    void accept(const Packet& p);
    void closeAndEmit(bool atEndOfFile);
    void scoreAndLearn(WindowResult& r);

    PipelineConfig config_;
    Sink sink_;
    WindowAggregator aggregator_;
    std::array<StatEngine, FEATURE_COUNT> engines_{};
    AnomalyScorer scorer_;
    PipelineCounters counters_;

    bool haveAccepted_ = false;
    double frontierTs_ = 0.0;      // latest accepted timestamp
    std::optional<Packet> held_;   // one-packet look-ahead for a far-future timestamp
    bool finished_ = false;
    int consecutiveAlerts_ = 0;    // gated-baseline state
};

} // namespace netsentinel
