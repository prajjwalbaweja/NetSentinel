#pragma once

#include "IAnomalyScorer.hpp"

namespace netsentinel {

// AnomalyScorer implements the decision/dedup contract defined in IAnomalyScorer: a feature triggers if
// its baseline isWarmedUp() and |z| > threshold; if one or more features trigger in the same window,
// exactly one AlertEvent is produced listing all of them.
//
// The threshold is a constructor argument (default DEFAULT_Z_THRESHOLD = 3.0), set from --threshold.
// Minimum standard deviation (SD floor): if a FeatureBaseline carries sd_floor > 0,
// z = (x - mean) / max(sigma, sd_floor); otherwise IStatEngine::zScore() is used unchanged
// (the original cumulative-baseline behaviour).
class AnomalyScorer : public IAnomalyScorer {
public:
    explicit AnomalyScorer(double threshold = DEFAULT_Z_THRESHOLD) : threshold_(threshold) {}

    std::optional<AlertEvent> evaluate(
        const WindowFeatures& window,
        const std::vector<FeatureBaseline>& baselines) override;

    // z-score used for the decision (NaN = not warmed up or inconclusive).
    static double effectiveZ(const FeatureBaseline& fb);

    double threshold() const { return threshold_; }

private:
    double threshold_;
};

} // namespace netsentinel
