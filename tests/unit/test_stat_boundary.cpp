// Mutant M07: the cumulative baseline's variance guard boundary (IStatEngine::VARIANCE_EPSILON = 1e-6).
// The original statistical-engine test only checks a perfectly constant baseline (variance 0), so changing the
// epsilon (e.g. 1e-6 -> 1e-5 or -> 1e-7) went undetected. These two cases bracket the threshold:
// a warmed-up baseline with variance about 5e-6 must give a finite z-score; one with variance about
// 5e-7 must give NaN. StatEngine itself is unchanged (the cumulative baseline stays the original policy).
#include <cmath>

#include <catch2/catch_test_macros.hpp>

#include "StatEngine.hpp"

using netsentinel::StatEngine;

namespace {
// 25 values: 13 zeros and 12 copies of d -> sample variance = d^2 * (13*12/25) / 24 = 0.26 d^2.
StatEngine alternating(double d) {
    StatEngine e;
    for (int i = 0; i < 25; ++i) e.update(i % 2 == 0 ? 0.0 : d);
    return e;
}
} // namespace

TEST_CASE("Variance just above epsilon gives a finite z-score", "[stat_engine][variance-epsilon]") {
    const StatEngine e = alternating(0.0044); // variance ~ 5.03e-6
    REQUIRE(e.isWarmedUp());
    REQUIRE(e.variance() > 2e-6);
    REQUIRE(e.variance() < 9e-6);
    const double z = e.zScore(1.0);
    REQUIRE(std::isfinite(z));
    REQUIRE(z > 3.0);
}

TEST_CASE("Variance just below epsilon gives NaN (inconclusive)", "[stat_engine][variance-epsilon]") {
    const StatEngine e = alternating(0.0014); // variance ~ 5.1e-7
    REQUIRE(e.isWarmedUp());
    REQUIRE(e.variance() > 1e-7);
    REQUIRE(e.variance() < 9e-7);
    REQUIRE(std::isnan(e.zScore(1.0)));
}
