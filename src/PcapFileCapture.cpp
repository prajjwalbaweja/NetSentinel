#include "PcapFileCapture.hpp"

namespace netsentinel {

PcapFileCapture::~PcapFileCapture() {
    close();
}

bool PcapFileCapture::open(const std::string& source) {
    close(); // reopening must release the previous handle (the original version leaked it)
    readError_ = false;
    lastError_.clear();
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    handle_ = pcap_open_offline(source.c_str(), errbuf);
    if (!handle_) {
        lastError_ = errbuf;
        return false;
    }
    return true;
}

std::optional<RawPacketView> PcapFileCapture::next() {
    if (!handle_) {
        return std::nullopt;
    }

    struct pcap_pkthdr* header = nullptr;
    const u_char* data = nullptr;
    const int result = pcap_next_ex(handle_, &header, &data);

    if (result != 1) {
        // 0 = timeout (not applicable to offline replay), -1 = read error
        // (e.g. "truncated dump file"), -2 = clean end of the PCAP file.
        // Every case still means "no more packets", but a read error is now
        // recorded so the caller can report it instead of treating it as EOF.
        if (result == -1) {
            readError_ = true;
            lastError_ = pcap_geterr(handle_);
        }
        return std::nullopt;
    }

    RawPacketView view;
    view.data = data;
    view.length = header->caplen;          // bytes actually captured/saved
    view.original_length = header->len;    // on-wire length, may exceed caplen
    view.capture_timestamp_sec =
        static_cast<double>(header->ts.tv_sec) + static_cast<double>(header->ts.tv_usec) / 1e6;
    return view;
}

int PcapFileCapture::linkType() const {
    return handle_ ? pcap_datalink(handle_) : -1;
}

void PcapFileCapture::close() {
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

} // namespace netsentinel
