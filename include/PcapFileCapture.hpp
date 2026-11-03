#pragma once

#include <string>

#include <pcap.h>

#include "IPacketCapture.hpp"

namespace netsentinel {

// PcapFileCapture is the concrete implementation of
// IPacketCapture: replays packets from a saved PCAP file via libpcap's
// pcap_open_offline / pcap_next_ex. This is the project's only ingestion
// path; live-interface capture is out of scope for this version.
//
// lastError() exposes libpcap's own diagnostic
// string after a failed open() (e.g. "No such file or directory",
// "unknown file format"), rather than discarding it. Not part of the
// IPacketCapture interface -- an extension specific to this concrete
// class, added because a live demonstration needs a diagnosable failure
// message, not just a generic "failed" with no reason.
class PcapFileCapture : public IPacketCapture {
public:
    PcapFileCapture() = default;
    ~PcapFileCapture() override;

    // The object owns a pcap_t*. Copying it would make two objects close the same
    // handle (heap-use-after-free found by the audit), so copy and move are disabled.
    PcapFileCapture(const PcapFileCapture&) = delete;
    PcapFileCapture& operator=(const PcapFileCapture&) = delete;
    PcapFileCapture(PcapFileCapture&&) = delete;
    PcapFileCapture& operator=(PcapFileCapture&&) = delete;

    bool open(const std::string& source) override;
    std::optional<RawPacketView> next() override;
    void close() override;

    const std::string& lastError() const { return lastError_; }

    // libpcap link-layer type of the open file (DLT_* value), or -1 if not open.
    int linkType() const;

    // True if next() stopped because libpcap reported a READ ERROR (for example a
    // truncated capture file) rather than a clean end of file. lastError() then holds
    // libpcap's message. Concrete-class extension; the IPacketCapture interface is unchanged.
    bool hadError() const { return readError_; }

private:
    pcap_t* handle_ = nullptr;
    std::string lastError_;
    bool readError_ = false;
};

} // namespace netsentinel
