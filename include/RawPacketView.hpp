#pragma once

#include <cstddef>
#include <cstdint>

namespace netsentinel {

// RawPacketView is a lightweight, non-owning view over one captured
// packet's raw bytes plus its capture timestamp. It exists so
// IPacketCapture's contract does not leak a specific capture library's
// types (e.g. libpcap's pcap_pkthdr) into the interface layer -- the
// concrete libpcap-based implementation is free to wrap
// libpcap's own structures into this view internally.
struct RawPacketView {
    const uint8_t* data = nullptr;
    std::size_t length = 0;              // bytes actually captured (caplen); bounds every read
    std::size_t original_length = 0;     // on-wire length (pcap orig_len)
    double capture_timestamp_sec = 0.0;
};

} // namespace netsentinel
