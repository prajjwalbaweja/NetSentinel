#pragma once

#include <cstdint>

#include "IFeatureExtractor.hpp"

namespace netsentinel {

// Why a packet was not turned into a PacketFeature (skipped traffic is counted by
// reason so an empty window can be told apart from traffic the parser cannot see).
enum class SkipReason : uint8_t {
    None = 0,
    TruncatedLinkHeader, // too short for the link-layer (or VLAN) header
    Ipv6,                // ethertype 0x86DD: counted, not analysed
    OtherEthertype,      // ARP, LLDP, ... anything that is neither IPv4 nor IPv6
    MalformedIpv4,       // IPv4 ethertype but the header fails a bounds or validity check
};

const char* skipReasonName(SkipReason r);

// FeatureExtractor parses link layer + IPv4 + TCP/UDP headers from raw bytes.
//
// Link layers: Ethernet (DLT_EN10MB = 1), including up to two 802.1Q / 802.1ad
// VLAN tags, and Linux cooked capture (DLT_LINUX_SLL = 113). Any other link type is rejected by
// the caller before extraction (main exits with an error instead of silently parsing nothing).
//
// IPv4 rules: version 4, IHL >= 5, declared header within the captured bytes. Ports are read
// only for TCP/UDP, only from the first fragment (fragment offset 0), and only when at
// least 4 transport bytes were captured. packet_size_bytes is the on-wire length, not the captured length.
class FeatureExtractor : public IFeatureExtractor {
public:
    static constexpr int LINKTYPE_ETHERNET = 1;
    static constexpr int LINKTYPE_LINUX_SLL = 113;

    explicit FeatureExtractor(int linkType = LINKTYPE_ETHERNET) : linkType_(linkType) {}

    static bool isSupportedLinkType(int linkType) {
        return linkType == LINKTYPE_ETHERNET || linkType == LINKTYPE_LINUX_SLL;
    }

    std::optional<PacketFeature> extract(const RawPacketView& packet) override;

    // Reason for the most recent extract() returning std::nullopt (None after a success).
    SkipReason lastSkipReason() const { return lastSkip_; }

private:
    int linkType_;
    SkipReason lastSkip_ = SkipReason::None;
};

} // namespace netsentinel
