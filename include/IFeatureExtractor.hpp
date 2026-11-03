#pragma once

#include <optional>

#include "PacketFeature.hpp"
#include "RawPacketView.hpp"

namespace netsentinel {

// IFeatureExtractor is the contract for turning one raw captured packet
// into a PacketFeature.
//
// Interface only; header parsing (Ethernet/IP/TCP/UDP) is implemented in
// FeatureExtractor.
class IFeatureExtractor {
public:
    virtual ~IFeatureExtractor() = default;

    // Returns std::nullopt if the packet cannot be parsed, or falls
    // outside the set of protocols NetSentinel tracks.
    virtual std::optional<PacketFeature> extract(const RawPacketView& packet) = 0;
};

} // namespace netsentinel
