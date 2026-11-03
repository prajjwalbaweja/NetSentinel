#pragma once

#include <cstdint>

namespace netsentinel {

// WindowFeatures represents the aggregated statistics for a single
// 5-second tumbling window. This is a pure data model — the logic that
// aggregates raw PacketFeature values into one of these belongs to
// WindowAggregator, not this file.
struct WindowFeatures {
    // Window boundaries, seconds since epoch.
    double window_start_sec = 0.0;
    double window_end_sec = 0.0;

    // Total parsed IPv4 packets observed in this window (the scored feature).
    uint32_t packet_count = 0;

    // Mean packet size (bytes) across this window.
    double avg_packet_size_bytes = 0.0;

    // Count of distinct destination ports touched in this window.
    uint32_t unique_dst_ports = 0;

    // Count of distinct destination IPs touched in this window.
    uint32_t unique_dst_ips = 0;

    // ---- Provenance. Lets the pipeline tell an idle window, a window whose traffic
    // the parser cannot see, and a normal window apart, and report why packets were not used.
    uint32_t raw_packet_count = 0;       // every packet whose timestamp fell in this window
    uint32_t skipped_truncated_link = 0; // ... of which: link header too short
    uint32_t skipped_ipv6 = 0;           // ... of which: IPv6 (counted, not analysed)
    uint32_t skipped_other_ethertype = 0;
    uint32_t skipped_malformed_ipv4 = 0;
    uint32_t late_dropped = 0;           // packets dropped as late while this window was open (time policy)
    uint32_t quarantined = 0;            // far-future packets quarantined while this window was open (time policy)
};

} // namespace netsentinel
