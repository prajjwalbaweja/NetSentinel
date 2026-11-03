#include "FeatureExtractor.hpp"

#include <cstdint>
#include <cstdio>

namespace netsentinel {

namespace {

uint16_t readU16BE(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

std::string ipv4ToString(const uint8_t* p) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return std::string(buf);
}

constexpr std::size_t ETH_HEADER_LEN = 14;
constexpr std::size_t VLAN_TAG_LEN = 4;
constexpr std::size_t SLL_HEADER_LEN = 16;
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
constexpr uint16_t ETHERTYPE_VLAN = 0x8100;   // 802.1Q
constexpr uint16_t ETHERTYPE_QINQ = 0x88A8;   // 802.1ad outer tag
constexpr int MAX_VLAN_TAGS = 2;
constexpr uint8_t PROTO_TCP = 6;
constexpr uint8_t PROTO_UDP = 17;
constexpr std::size_t MIN_IPV4_HEADER_LEN = 20;
constexpr std::size_t PORT_BYTES = 4;          // src port + dst port: all that is needed
constexpr uint16_t FRAGMENT_OFFSET_MASK = 0x1FFF;

} // namespace

const char* skipReasonName(SkipReason r) {
    switch (r) {
        case SkipReason::None: return "none";
        case SkipReason::TruncatedLinkHeader: return "truncated_link_header";
        case SkipReason::Ipv6: return "ipv6";
        case SkipReason::OtherEthertype: return "other_ethertype";
        case SkipReason::MalformedIpv4: return "malformed_ipv4";
    }
    return "unknown";
}

std::optional<PacketFeature> FeatureExtractor::extract(const RawPacketView& packet) {
    lastSkip_ = SkipReason::None;
    const auto skip = [this](SkipReason r) -> std::optional<PacketFeature> {
        lastSkip_ = r;
        return std::nullopt;
    };

    if (packet.data == nullptr) {
        return skip(SkipReason::TruncatedLinkHeader);
    }

    // ---- Link layer: find the network-layer offset and ethertype.
    std::size_t ipOffset = 0;
    uint16_t ethertype = 0;
    if (linkType_ == LINKTYPE_LINUX_SLL) {
        if (packet.length < SLL_HEADER_LEN) {
            return skip(SkipReason::TruncatedLinkHeader);
        }
        ethertype = readU16BE(packet.data + 14);
        ipOffset = SLL_HEADER_LEN;
    } else {
        if (packet.length < ETH_HEADER_LEN) {
            return skip(SkipReason::TruncatedLinkHeader);
        }
        std::size_t typeOffset = 12;
        ethertype = readU16BE(packet.data + typeOffset);
        int tags = 0;
        while ((ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ) && tags < MAX_VLAN_TAGS) {
            typeOffset += VLAN_TAG_LEN;
            if (packet.length < typeOffset + 2) {
                return skip(SkipReason::TruncatedLinkHeader);
            }
            ethertype = readU16BE(packet.data + typeOffset);
            ++tags;
        }
        ipOffset = typeOffset + 2;
    }

    if (ethertype == ETHERTYPE_IPV6) {
        return skip(SkipReason::Ipv6);
    }
    if (ethertype != ETHERTYPE_IPV4) {
        return skip(SkipReason::OtherEthertype);
    }

    // ---- IPv4 header.
    if (packet.length < ipOffset + MIN_IPV4_HEADER_LEN) {
        return skip(SkipReason::MalformedIpv4); // not enough bytes for a minimal IPv4 header
    }
    const uint8_t versionIhl = packet.data[ipOffset];
    const uint8_t version = versionIhl >> 4;
    const uint8_t ihl = versionIhl & 0x0F;
    if (version != 4 || ihl < 5) {
        return skip(SkipReason::MalformedIpv4);
    }
    const std::size_t ipHeaderLen = static_cast<std::size_t>(ihl) * 4;
    if (packet.length < ipOffset + ipHeaderLen) {
        return skip(SkipReason::MalformedIpv4); // declared header length exceeds captured bytes
    }

    PacketFeature feature{};
    feature.timestamp_sec = packet.capture_timestamp_sec;
    const std::size_t wireLen = packet.original_length > 0 ? packet.original_length : packet.length;
    feature.packet_size_bytes = static_cast<uint32_t>(wireLen);
    feature.protocol = packet.data[ipOffset + 9];
    feature.src_ip = ipv4ToString(packet.data + ipOffset + 12);
    feature.dst_ip = ipv4ToString(packet.data + ipOffset + 16);

    // ---- Transport ports: TCP/UDP, first fragment only, at least 4 captured transport bytes.
    const uint16_t fragmentOffset = readU16BE(packet.data + ipOffset + 6) & FRAGMENT_OFFSET_MASK;
    const std::size_t transportOffset = ipOffset + ipHeaderLen;
    const bool tcpOrUdp = feature.protocol == PROTO_TCP || feature.protocol == PROTO_UDP;
    if (tcpOrUdp && fragmentOffset == 0 && packet.length >= transportOffset + PORT_BYTES) {
        feature.src_port = readU16BE(packet.data + transportOffset);
        feature.dst_port = readU16BE(packet.data + transportOffset + 2);
        feature.has_ports = true;
    }

    return feature;
}

} // namespace netsentinel
