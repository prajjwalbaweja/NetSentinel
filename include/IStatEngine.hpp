#pragma once

namespace netsentinel {

// IStatEngine is the contract for one feature's running statistics.
// One instance is used per tracked feature -- see the fixed feature set
// below -- not one shared instance across features. StatEngine
// implements it with Welford's online algorithm.
//
// Fixed feature set -- exactly four
// IStatEngine instances exist at runtime, one per feature:
//   1. packet_count      (per window)
//   2. avg_packet_size   (per window)
//   3. unique_dst_ports  (per window)
//   4. unique_dst_ips    (per window)
//
// Warm-up policy: the first
// WARMUP_WINDOW_COUNT windows only update the running statistics -- they
// never produce a z-score or feed an anomaly decision. This avoids
// scoring against a baseline that has not stabilized yet. 20 windows
// (100 seconds of traffic at 5s/window) was chosen as a simple,
// defensible starting point -- it is a fixed constant, not a derived
// value, and was not tuned on the evaluation data.
//
// Near-zero-variance guard: if the
// running variance falls below VARIANCE_EPSILON, zScore() must not
// divide by it; StatEngine returns NaN ("inconclusive") in that case.
// This interface fixes the threshold below which that guard applies.
//
// Interface only: no Welford or z-score math is implemented here.
class IStatEngine {
public:
    static constexpr int WARMUP_WINDOW_COUNT = 20;
    static constexpr double VARIANCE_EPSILON = 1e-6;

    virtual ~IStatEngine() = default;

    // Folds one new observed value into the running statistics
    // (Welford's incremental update, implemented in StatEngine).
    virtual void update(double value) = 0;

    virtual double mean() const = 0;
    virtual double variance() const = 0;

    // True once WARMUP_WINDOW_COUNT values have been observed.
    virtual bool isWarmedUp() const = 0;

    // Returns the z-score of `value` against the current running
    // mean/variance. Callers must check isWarmedUp() first. Behavior
    // when variance is below VARIANCE_EPSILON is defined by the
    // implementation (StatEngine returns NaN).
    virtual double zScore(double value) const = 0;
};

} // namespace netsentinel
