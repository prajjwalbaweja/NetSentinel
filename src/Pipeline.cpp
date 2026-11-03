#include "Pipeline.hpp"

#include <cmath>
#include <limits>
#include <string>
#include <vector>

namespace netsentinel {

const std::array<const char*, FEATURE_COUNT> FEATURE_NAMES = {
    "packet_count", "avg_packet_size", "unique_dst_ports", "unique_dst_ips"};

const char* windowStatusName(WindowStatus s) {
    switch (s) {
        case WindowStatus::Scored: return "scored";
        case WindowStatus::Idle: return "idle";
        case WindowStatus::NoParsedTraffic: return "no_parsed_traffic";
        case WindowStatus::Partial: return "partial";
    }
    return "unknown";
}

const char* baselineActionName(BaselineAction a) {
    switch (a) {
        case BaselineAction::Updated: return "updated";
        case BaselineAction::NotLearned: return "not_learned";
        case BaselineAction::Gated: return "gated";
        case BaselineAction::ForcedUpdate: return "forced_update";
        case BaselineAction::Frozen: return "frozen";
    }
    return "unknown";
}

const char* baselinePolicyName(BaselinePolicy p) {
    switch (p) {
        case BaselinePolicy::Cumulative: return "cumulative";
        case BaselinePolicy::Gated: return "gated";
        case BaselinePolicy::Frozen: return "frozen";
    }
    return "unknown";
}

Pipeline::Pipeline(PipelineConfig config, Sink sink)
    : config_(config), sink_(std::move(sink)), scorer_(config.threshold) {}

void Pipeline::onPacket(double timestampSec, const std::optional<PacketFeature>& feature, SkipReason reason) {
    ++counters_.packetsRead;
    Packet p{timestampSec, feature, reason};

    if (held_) {
        const Packet held = *held_;
        held_.reset();
        if (p.ts <= frontierTs_ + config_.gapCapSec) {
            // Back on the old timeline: the held packet was an isolated far-future glitch.
            ++counters_.quarantined;
            aggregator_.noteQuarantined();
            accept(p);
        } else {
            // Still far ahead: the jump is real time.
            accept(held);
            accept(p);
        }
        return;
    }

    if (haveAccepted_ && p.ts > frontierTs_ + config_.gapCapSec) {
        held_ = p; // decide when the next packet (or end of file) arrives
        return;
    }
    accept(p);
}

void Pipeline::accept(const Packet& p) {
    if (!aggregator_.started()) {
        aggregator_.start(p.ts);
    }

    if (p.ts < aggregator_.windowStart()) {
        ++counters_.lateDropped;
        aggregator_.noteLateDropped();
        return;
    }

    if (aggregator_.isWindowComplete(p.ts)) {
        closeAndEmit(false); // the window that was open
        const long emptyWindows = aggregator_.windowsUntil(p.ts);
        const long capWindows = static_cast<long>(
            std::floor(config_.gapCapSec / IWindowAggregator::WINDOW_LENGTH_SEC));
        if (emptyWindows > capWindows) {
            for (long i = 0; i < capWindows; ++i) {
                closeAndEmit(false);
            }
            const long rest = aggregator_.windowsUntil(p.ts);
            aggregator_.skipWindows(rest);
            counters_.idleWindowsSuppressed += rest;
            ++counters_.gapCaps;
        } else {
            for (long i = 0; i < emptyWindows; ++i) {
                closeAndEmit(false);
            }
        }
    }

    if (!haveAccepted_ || p.ts > frontierTs_) {
        frontierTs_ = p.ts;
    }
    haveAccepted_ = true;

    if (p.feature) {
        ++counters_.packetsParsed;
        aggregator_.addPacket(*p.feature);
    } else {
        switch (p.reason) {
            case SkipReason::TruncatedLinkHeader: ++counters_.skippedTruncatedLink; break;
            case SkipReason::Ipv6: ++counters_.skippedIpv6; break;
            case SkipReason::OtherEthertype: ++counters_.skippedOtherEthertype; break;
            case SkipReason::MalformedIpv4: ++counters_.skippedMalformedIpv4; break;
            case SkipReason::None: ++counters_.skippedMalformedIpv4; break; // defensive: never expected
        }
        aggregator_.addSkipped(p.reason);
    }
}

void Pipeline::closeAndEmit(bool atEndOfFile) {
    WindowResult r;
    r.index = static_cast<int>(counters_.windowsEmitted);
    r.features = aggregator_.closeWindow();
    r.zState.fill(ZState::NotScored);
    r.z.fill(std::numeric_limits<double>::quiet_NaN());

    if (atEndOfFile) {
        r.status = WindowStatus::Partial;
        ++counters_.windowsPartial;
    } else if (r.features.raw_packet_count == 0) {
        r.status = WindowStatus::Idle;
        ++counters_.windowsIdle;
    } else if (r.features.packet_count == 0) {
        r.status = WindowStatus::NoParsedTraffic;
        ++counters_.windowsNoParsedTraffic;
    } else {
        r.status = WindowStatus::Scored;
        ++counters_.windowsScored;
        scoreAndLearn(r);
    }

    ++counters_.windowsEmitted;
    if (sink_) {
        sink_(r);
    }
}

void Pipeline::scoreAndLearn(WindowResult& r) {
    const WindowFeatures& w = r.features;
    const std::array<double, FEATURE_COUNT> values = {
        static_cast<double>(w.packet_count), w.avg_packet_size_bytes,
        static_cast<double>(w.unique_dst_ports), static_cast<double>(w.unique_dst_ips)};

    const bool useFloor = config_.policy == BaselinePolicy::Gated && config_.sdFloorEnabled;
    std::vector<FeatureBaseline> baselines;
    for (int k = 0; k < FEATURE_COUNT; ++k) {
        baselines.push_back({FEATURE_NAMES[k], values[k], &engines_[k], useFloor ? config_.sdFloor[k] : 0.0});
        if (!engines_[k].isWarmedUp()) {
            r.zState[k] = ZState::Warmup;
            continue;
        }
        const double z = AnomalyScorer::effectiveZ(baselines.back());
        r.z[k] = z;
        r.zState[k] = std::isnan(z) ? ZState::NotAvailable : ZState::Value;
    }

    r.alert = scorer_.evaluate(w, baselines);
    if (r.alert) {
        ++counters_.alerts;
    }

    // Score-then-update, by policy. The four engines always move together.
    bool learn = true;
    switch (config_.policy) {
        case BaselinePolicy::Cumulative: // original policy, unchanged: every scored window is learned
            r.action = BaselineAction::Updated;
            break;
        case BaselinePolicy::Gated:
            if (r.alert) {
                ++consecutiveAlerts_;
                if (consecutiveAlerts_ > config_.recoveryWindows) {
                    r.action = BaselineAction::ForcedUpdate; // recovery limit: no permanent lockout
                } else {
                    r.action = BaselineAction::Gated;
                    learn = false;
                }
            } else {
                consecutiveAlerts_ = 0;
                r.action = BaselineAction::Updated;
            }
            break;
        case BaselinePolicy::Frozen:
            if (engines_[0].isWarmedUp()) {
                r.action = BaselineAction::Frozen;
                learn = false;
            } else {
                r.action = BaselineAction::Updated;
            }
            break;
    }
    if (learn) {
        for (int k = 0; k < FEATURE_COUNT; ++k) {
            engines_[k].update(values[k]);
        }
    }
    r.consecutiveAlerts = consecutiveAlerts_;
}

void Pipeline::finish() {
    if (finished_) {
        return;
    }
    finished_ = true;
    if (held_) {
        ++counters_.quarantined; // a far-future packet at end of file: no evidence it was real
        aggregator_.noteQuarantined();
        held_.reset();
    }
    if (aggregator_.started()) {
        closeAndEmit(true); // the window open at end of file is partial (not scored or learned)
    }
}

} // namespace netsentinel
