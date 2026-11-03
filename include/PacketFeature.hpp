#pragma once

#include <cstdint>
#include <string>

namespace netsentinel {

// PacketFeature represents the set of fields extracted from a single
// captured packet. This is a pure data model — no capture logic, no
// parsing logic. Population of this struct from raw libpcap data is
// FeatureExtractor's responsibility, not this file's.
struct PacketFeature {
    // Capture timestamp, seconds since epoch (fractional).
    double timestamp_sec = 0.0;

    // Total on-wire packet size in bytes (taken from the pcap original length,
    // not from the captured length, so snaplen truncation does not change it).
    uint32_t packet_size_bytes = 0;

    // Transport-layer protocol identifier (e.g. IPPROTO_TCP, IPPROTO_UDP).
    uint8_t protocol = 0;

    // Source and destination IPv4 addresses, dotted-decimal string form.
    std::string src_ip;
    std::string dst_ip;

    // Source and destination ports. 0 if not applicable to the protocol.
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    // True only when the ports were actually read from a transport header
    // (TCP/UDP, first fragment, at least 4 transport bytes captured). The aggregator counts a
    // destination port only when this is true, so phantom ports (0 or payload bytes) never count.
    bool has_ports = false;
};

} // namespace netsentinel
