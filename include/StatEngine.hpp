#pragma once

#include "IStatEngine.hpp"

namespace netsentinel {

// StatEngine is the concrete implementation of IStatEngine:
// Welford's online algorithm for running mean/variance, plus the
// warm-up and near-zero-variance safeguards whose thresholds are defined
// in the interface (IStatEngine::WARMUP_WINDOW_COUNT,
// IStatEngine::VARIANCE_EPSILON).
//
// This class has no knowledge of packets, windows, or capture -- it only
// ever sees the sequence of double values passed to update(). That
// independence from packet I/O is deliberate: Pipeline connects the
// feature value streams to it.
class StatEngine : public IStatEngine {
public:
    void update(double value) override;

    double mean() const override;
    double variance() const override;
    bool isWarmedUp() const override;
    double zScore(double value) const override;

private:
    int count_ = 0;
    double mean_ = 0.0;
    double m2_ = 0.0; // running sum of squared differences from the mean
};

} // namespace netsentinel
