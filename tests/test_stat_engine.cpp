#include <cmath>

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include "StatEngine.hpp"

using Catch::Approx;
using netsentinel::StatEngine;

TEST_CASE("Welford mean and variance match a hand-calculated textbook dataset", "[stat_engine]") {
    // Dataset {2, 4, 4, 4, 5, 5, 7, 9} (the standard Welford's-algorithm
    // worked example). By hand: sum = 40, n = 8, mean = 5.
    // Squared deviations: 9, 1, 1, 1, 0, 0, 4, 16 -> sum = 32.
    // Sample variance = 32 / (8 - 1) = 32/7.
    StatEngine engine;
    for (double v : {2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0}) {
        engine.update(v);
    }

    REQUIRE(engine.mean() == Approx(5.0));
    REQUIRE(engine.variance() == Approx(32.0 / 7.0));
}

TEST_CASE("Incremental updates match hand-calculated running mean/variance at each step",
          "[stat_engine]") {
    // Verifies Welford's algorithm is genuinely incremental -- checked
    // after every single update, not just once at the end.
    StatEngine engine;

    engine.update(10.0);
    REQUIRE(engine.mean() == Approx(10.0));
    REQUIRE(engine.variance() == 0.0); // count_ < 2 guard, exact

    engine.update(12.0);
    // mean = (10+12)/2 = 11; squared deviations: 1, 1 -> variance = 2/(2-1) = 2
    REQUIRE(engine.mean() == Approx(11.0));
    REQUIRE(engine.variance() == Approx(2.0));

    engine.update(14.0);
    // mean = (10+12+14)/3 = 12; squared deviations: 4, 0, 4 -> variance = 8/(3-1) = 4
    REQUIRE(engine.mean() == Approx(12.0));
    REQUIRE(engine.variance() == Approx(4.0));
}

TEST_CASE("Warm-up: no z-score until WARMUP_WINDOW_COUNT samples are observed",
          "[stat_engine][warmup]") {
    StatEngine engine;

    for (int i = 0; i < StatEngine::WARMUP_WINDOW_COUNT - 1; ++i) {
        engine.update(100.0 + i); // varying values so variance is nonzero
        REQUIRE_FALSE(engine.isWarmedUp());
        REQUIRE(std::isnan(engine.zScore(999.0)));
    }

    engine.update(200.0); // the WARMUP_WINDOW_COUNT-th sample
    REQUIRE(engine.isWarmedUp());
}

TEST_CASE("Near-zero variance: zScore returns NaN, not Inf or a divide-by-zero artifact",
          "[stat_engine][edge_case]") {
    StatEngine engine;
    // Enough identical values to be warmed up with (near-)zero variance.
    for (int i = 0; i < StatEngine::WARMUP_WINDOW_COUNT + 5; ++i) {
        engine.update(42.0);
    }

    REQUIRE(engine.isWarmedUp());
    REQUIRE(engine.variance() < StatEngine::VARIANCE_EPSILON);
    REQUIRE(std::isnan(engine.zScore(999.0)));
}

TEST_CASE("Z-score calculation matches a hand-calculated value", "[stat_engine][zscore]") {
    // Feed 1..25. Closed-form for an arithmetic sequence 1..n:
    //   mean = (n+1)/2 = 13
    //   sum of squared deviations = n(n^2-1)/12 = 25*(625-1)/12 = 1300
    //   sample variance = 1300 / (25-1) = 1300/24
    StatEngine engine;
    for (int i = 1; i <= 25; ++i) {
        engine.update(static_cast<double>(i));
    }

    const double expectedMean = 13.0;
    const double expectedVariance = 1300.0 / 24.0;
    const double expectedStd = std::sqrt(expectedVariance);
    const double expectedZ = (100.0 - expectedMean) / expectedStd;

    REQUIRE(engine.mean() == Approx(expectedMean));
    REQUIRE(engine.variance() == Approx(expectedVariance));
    REQUIRE(engine.zScore(100.0) == Approx(expectedZ));
}
