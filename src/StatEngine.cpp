#include "StatEngine.hpp"

#include <cmath>
#include <limits>

namespace netsentinel {

void StatEngine::update(double value) {
    // Welford's online algorithm: folds one new value into the running
    // mean and the running sum of squared differences (m2_) in O(1) time
    // and memory, without storing the full history of values and without
    // the numerical instability a naive sum-of-squares variance formula
    // develops over a long-running process.
    ++count_;
    const double delta = value - mean_;
    mean_ += delta / static_cast<double>(count_);
    const double delta2 = value - mean_;
    m2_ += delta * delta2;
}

double StatEngine::mean() const {
    return mean_;
}

double StatEngine::variance() const {
    // Sample variance (Bessel's correction, dividing by n-1). Undefined
    // for fewer than 2 samples -- return 0.0 rather than dividing by
    // zero. Callers that need a meaningful variance should be checking
    // isWarmedUp() first (the IStatEngine contract), which guarantees
    // count_ >= 20 by the time variance() is treated as meaningful.
    if (count_ < 2) {
        return 0.0;
    }
    return m2_ / static_cast<double>(count_ - 1);
}

bool StatEngine::isWarmedUp() const {
    return count_ >= WARMUP_WINDOW_COUNT;
}

double StatEngine::zScore(double value) const {
    // Both guards return NaN rather than a numeric-looking value such as
    // 0.0. A silently-returned 0.0 could be misread downstream as
    // "no anomaly" -- a false negative baked into the return value. NaN
    // forces any caller that skips the isWarmedUp() check to notice,
    // since NaN propagates through arithmetic and fails comparisons
    // rather than looking like a normal, unremarkable score.
    if (!isWarmedUp()) {
        return std::numeric_limits<double>::quiet_NaN();
    }

    const double var = variance();
    if (var < VARIANCE_EPSILON) {
        return std::numeric_limits<double>::quiet_NaN();
    }

    return (value - mean_) / std::sqrt(var);
}

} // namespace netsentinel
