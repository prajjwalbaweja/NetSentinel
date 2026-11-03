#pragma once

#include <optional>
#include <string>

#include "RawPacketView.hpp"

namespace netsentinel {

// IPacketCapture is the contract for any packet ingestion backend.
//
// Interface only; the concrete implementation (PCAP-file replay via
// libpcap) is PcapFileCapture. No parsing, no libpcap calls, and no I/O
// happen in this file.
//
// Scope note: only file-based PCAP replay is implemented. Live-interface
// capture is out of scope for this version.
class IPacketCapture {
public:
    virtual ~IPacketCapture() = default;

    // Opens a capture source. For the current scope this is always a
    // PCAP file path.
    virtual bool open(const std::string& source) = 0;

    // Returns the next raw packet, or std::nullopt once the source is
    // exhausted (end of file for PCAP replay).
    virtual std::optional<RawPacketView> next() = 0;

    virtual void close() = 0;
};

} // namespace netsentinel
