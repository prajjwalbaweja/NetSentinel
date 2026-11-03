#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace netsentinel {

// TriggeredFeature records that a single feature crossed the anomaly
// threshold within a window, and by how much.
struct TriggeredFeature {
    std::string feature_name;   // e.g. "packet_count", "unique_dst_ports"
    double observed_value = 0.0;
    double z_score = 0.0;
};

// AlertEvent represents ONE anomaly event for ONE window. Per the locked
// roadmap's dedup rule, a window that trips multiple feature thresholds
// produces a single AlertEvent listing every triggered feature — not one
// AlertEvent per feature. The logic that decides what counts as
// "triggered" and populates this struct belongs to AnomalyScorer
// (see AnomalyScorer.cpp), not this file.
struct AlertEvent {
    double window_start_sec = 0.0;
    double window_end_sec = 0.0;

    std::vector<TriggeredFeature> triggered_features;
};

} // namespace netsentinel
