#pragma once

#include <optional>
#include <string>
#include <vector>

#include "AlertEvent.hpp"
#include "IStatEngine.hpp"
#include "WindowFeatures.hpp"

namespace netsentinel {

// One tracked feature's observed value in the current window, paired
// with the IStatEngine maintaining its running baseline. This is what
// IAnomalyScorer needs, per feature, to decide whether that feature
// triggered in the current window.
struct FeatureBaseline {
    std::string feature_name;
    double observed_value = 0.0;
    IStatEngine* baseline = nullptr; // non-owning

    // Minimum standard deviation (SD floor), used by the gated baseline only when --sd-floor is set:
    // sigma_effective = max(sigma, sd_floor). 0 (the default) means the original rule: variance below
    // IStatEngine::VARIANCE_EPSILON gives an inconclusive (NaN) z-score, as in the original prototype.
    double sd_floor = 0.0;
};

// IAnomalyScorer is the contract for turning one window's observed
// feature values, plus each feature's running baseline, into at most
// one AlertEvent.
//
// Anomaly decision + deduplication contract:
//   - Default z-score threshold: DEFAULT_Z_THRESHOLD (configurable with
//     --threshold; not tuned on the evaluation data).
//   - A feature "triggers" if its baseline isWarmedUp() AND
//     |zScore| > threshold.
//   - If zero features trigger in a window, evaluate() returns
//     std::nullopt -- no AlertEvent, no alert emitted.
//   - If one or more features trigger in the same window, exactly ONE
//     AlertEvent is produced, listing every triggered feature as a
//     TriggeredFeature entry -- never one AlertEvent per feature. This
//     is the multi-feature deduplication rule of the AlertEvent data model.
//
// Interface only; the threshold check and AlertEvent assembly are in
// AnomalyScorer.
class IAnomalyScorer {
public:
    static constexpr double DEFAULT_Z_THRESHOLD = 3.0;

    virtual ~IAnomalyScorer() = default;

    virtual std::optional<AlertEvent> evaluate(
        const WindowFeatures& window,
        const std::vector<FeatureBaseline>& baselines) = 0;
};

} // namespace netsentinel
