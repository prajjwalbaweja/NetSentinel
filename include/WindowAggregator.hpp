#pragma once

#include <set>
#include <string>

#include "FeatureExtractor.hpp"
#include "IWindowAggregator.hpp"

namespace netsentinel {

// WindowAggregator implements the tumbling-window contract: fixed 5 s, non-overlapping windows on
// a grid aligned to the timestamp of the first packet ever seen.
//
// Changes from the original prototype:
//  - The grid is started by start(ts) with the first packet of ANY kind (time advances on
//    every timestamped packet, not only on parsed IPv4 packets).
//  - Skipped and late packets are recorded as window provenance.
//  - skipToWindowContaining(ts) jumps the grid forward by whole windows, keeping alignment, so an
//    idle gap does not have to be walked window by window (idle-gap cap).
//
// A dst port is counted only for TCP/UDP packets whose ports were actually read (has_ports).
class WindowAggregator : public IWindowAggregator {
public:
    void start(double timestampSec);
    bool started() const { return started_; }
    double windowStart() const { return windowStart_; }
    double windowEnd() const { return windowEnd_; }

    void addPacket(const PacketFeature& packet) override;
    void addSkipped(SkipReason reason);
    void noteLateDropped() { ++lateDropped_; }
    void noteQuarantined() { ++quarantined_; }

    bool isWindowComplete(double latestTimestampSec) const override;
    WindowFeatures closeWindow() override;

    // Number of whole windows between the current window start and the window containing ts.
    long windowsUntil(double timestampSec) const;
    // Advances the grid by `windows` whole windows without emitting them (current window must be empty).
    void skipWindows(long windows);

    // True once addPacket() has been called since construction or the last closeWindow().
    bool hasPendingPacket() const;

private:
    bool started_ = false;
    double windowStart_ = 0.0;
    double windowEnd_ = 0.0;

    uint32_t packetCount_ = 0;
    double sumPacketSize_ = 0.0;
    std::set<uint16_t> uniqueDstPorts_;
    std::set<std::string> uniqueDstIps_;

    uint32_t rawCount_ = 0;
    uint32_t skippedTruncLink_ = 0;
    uint32_t skippedIpv6_ = 0;
    uint32_t skippedOther_ = 0;
    uint32_t skippedMalformed_ = 0;
    uint32_t lateDropped_ = 0;
    uint32_t quarantined_ = 0;
};

} // namespace netsentinel
