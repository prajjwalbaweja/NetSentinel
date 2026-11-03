#pragma once

#include "PacketFeature.hpp"
#include "WindowFeatures.hpp"

namespace netsentinel {

// IWindowAggregator is the contract for bucketing PacketFeature values
// into fixed, non-overlapping 5-second tumbling windows and producing
// one WindowFeatures per window.
//
// Window contract:
//   - Windows are tumbling, not sliding: [t, t+5s), [t+5s, t+10s), ...
//     with no overlap between consecutive windows.
//   - A packet belongs to exactly one window, determined by its
//     capture timestamp.
//   - A window is closed once a packet arrives whose timestamp falls
//     at or past the window's end boundary, or once the capture source
//     is exhausted. The final window, open at end of
//     file, is closed and REPORTED as partial but is neither scored nor
//     learned (see Pipeline::finish). Idle and no-parsed-traffic windows
//     are likewise reported but neither scored nor learned.
//   - Known, accepted limitation: an attack that straddles a window
//     boundary may be split across two windows rather than
//     concentrated in one, and could under-trigger both. This is not
//     addressed by overlapping/sliding windows -- that was considered
//     and rejected as unnecessary complexity for this version.
//     It is documented as a known limitation, not silently ignored.
//
// Interface only; the bucketing logic is implemented in WindowAggregator.
class IWindowAggregator {
public:
    static constexpr double WINDOW_LENGTH_SEC = 5.0;

    virtual ~IWindowAggregator() = default;

    // Adds one packet's features to the window currently being built.
    virtual void addPacket(const PacketFeature& packet) = 0;

    // True once the window currently being built should be closed,
    // given the latest observed timestamp.
    virtual bool isWindowComplete(double latestTimestampSec) const = 0;

    // Closes the current window, returns its aggregated WindowFeatures,
    // and internally starts the next window.
    virtual WindowFeatures closeWindow() = 0;
};

} // namespace netsentinel
