#include "WindowAggregator.hpp"

#include <cmath>

namespace netsentinel {

namespace {
constexpr uint8_t PROTO_TCP = 6;
constexpr uint8_t PROTO_UDP = 17;
} // namespace

void WindowAggregator::start(double timestampSec) {
    if (started_) {
        return;
    }
    windowStart_ = timestampSec;
    windowEnd_ = windowStart_ + WINDOW_LENGTH_SEC;
    started_ = true;
}

void WindowAggregator::addPacket(const PacketFeature& packet) {
    start(packet.timestamp_sec); // no-op once started (kept for callers that never call start())

    ++rawCount_;
    ++packetCount_;
    sumPacketSize_ += static_cast<double>(packet.packet_size_bytes);

    // dst_ip is meaningful for any parsed IPv4 packet, regardless of transport protocol.
    uniqueDstIps_.insert(packet.dst_ip);

    // Only ports actually read from a transport header count.
    if ((packet.protocol == PROTO_TCP || packet.protocol == PROTO_UDP) && packet.has_ports) {
        uniqueDstPorts_.insert(packet.dst_port);
    }
}

void WindowAggregator::addSkipped(SkipReason reason) {
    ++rawCount_;
    switch (reason) {
        case SkipReason::TruncatedLinkHeader: ++skippedTruncLink_; break;
        case SkipReason::Ipv6: ++skippedIpv6_; break;
        case SkipReason::OtherEthertype: ++skippedOther_; break;
        case SkipReason::MalformedIpv4: ++skippedMalformed_; break;
        case SkipReason::None: break;
    }
}

bool WindowAggregator::isWindowComplete(double latestTimestampSec) const {
    return started_ && (latestTimestampSec >= windowEnd_);
}

bool WindowAggregator::hasPendingPacket() const {
    return packetCount_ > 0;
}

long WindowAggregator::windowsUntil(double timestampSec) const {
    if (!started_ || timestampSec < windowEnd_) {
        return 0;
    }
    return static_cast<long>(std::floor((timestampSec - windowStart_) / WINDOW_LENGTH_SEC));
}

void WindowAggregator::skipWindows(long windows) {
    if (windows <= 0) {
        return;
    }
    windowStart_ += static_cast<double>(windows) * WINDOW_LENGTH_SEC;
    windowEnd_ = windowStart_ + WINDOW_LENGTH_SEC;
}

WindowFeatures WindowAggregator::closeWindow() {
    WindowFeatures result;
    result.window_start_sec = windowStart_;
    result.window_end_sec = windowEnd_;
    result.packet_count = packetCount_;
    result.avg_packet_size_bytes =
        (packetCount_ > 0) ? (sumPacketSize_ / static_cast<double>(packetCount_)) : 0.0;
    result.unique_dst_ports = static_cast<uint32_t>(uniqueDstPorts_.size());
    result.unique_dst_ips = static_cast<uint32_t>(uniqueDstIps_.size());
    result.raw_packet_count = rawCount_;
    result.skipped_truncated_link = skippedTruncLink_;
    result.skipped_ipv6 = skippedIpv6_;
    result.skipped_other_ethertype = skippedOther_;
    result.skipped_malformed_ipv4 = skippedMalformed_;
    result.late_dropped = lateDropped_;
    result.quarantined = quarantined_;

    // Advance the fixed grid by exactly one window length.
    windowStart_ = windowEnd_;
    windowEnd_ = windowStart_ + WINDOW_LENGTH_SEC;
    packetCount_ = 0;
    sumPacketSize_ = 0.0;
    uniqueDstPorts_.clear();
    uniqueDstIps_.clear();
    rawCount_ = skippedTruncLink_ = skippedIpv6_ = skippedOther_ = skippedMalformed_ = 0;
    lateDropped_ = quarantined_ = 0;

    return result;
}

} // namespace netsentinel
