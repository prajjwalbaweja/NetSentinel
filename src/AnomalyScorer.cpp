#include "AnomalyScorer.hpp"

#include <cmath>
#include <limits>

namespace netsentinel {

double AnomalyScorer::effectiveZ(const FeatureBaseline& fb) {
    if (fb.baseline == nullptr || !fb.baseline->isWarmedUp()) {
        return std::numeric_limits<double>::quiet_NaN();
    }
    if (fb.sd_floor > 0.0) {
        // SD floor (gated baseline only): sigma_effective = max(sigma, floor). Never NaN once warmed up.
        const double sigma = std::sqrt(fb.baseline->variance());
        return (fb.observed_value - fb.baseline->mean()) / std::fmax(sigma, fb.sd_floor);
    }
    return fb.baseline->zScore(fb.observed_value); // original rule, NaN below VARIANCE_EPSILON
}

std::optional<AlertEvent> AnomalyScorer::evaluate(
    const WindowFeatures& window,
    const std::vector<FeatureBaseline>& baselines) {

    std::vector<TriggeredFeature> triggered;

    for (const auto& fb : baselines) {
        if (fb.baseline == nullptr || !fb.baseline->isWarmedUp()) {
            continue; // not warmed up yet -- never scored (warm-up rule: 20 windows)
        }

        const double z = effectiveZ(fb);
        if (std::isnan(z)) {
            continue; // near-zero-variance guard tripped inside StatEngine -- inconclusive
        }

        if (std::fabs(z) > threshold_) {
            TriggeredFeature tf;
            tf.feature_name = fb.feature_name;
            tf.observed_value = fb.observed_value;
            tf.z_score = z;
            triggered.push_back(tf);
        }
    }

    if (triggered.empty()) {
        return std::nullopt;
    }

    AlertEvent event;
    event.window_start_sec = window.window_start_sec;
    event.window_end_sec = window.window_end_sec;
    event.triggered_features = std::move(triggered);
    return event;
}

} // namespace netsentinel
