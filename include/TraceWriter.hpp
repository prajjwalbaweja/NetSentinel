#pragma once

#include <fstream>
#include <string>
#include <vector>

#include "Pipeline.hpp"

namespace netsentinel {

// Machine-readable per-window trace for evaluation (--trace); read errors are recorded in it.
// One CSV row per emitted window (scored, idle, no_parsed_traffic, partial). Lines starting with
// '#' are metadata: a header block (format version, input, configuration) and a footer block
// (run status and every counter). The console output is unaffected by the trace.
//
// Columns (format netsentinel-trace v1):
//   window_index, window_start, window_end, status, raw_packets, parsed_packets,
//   skipped_ipv6, skipped_other_ethertype, skipped_malformed_ipv4, skipped_truncated_link,
//   late_dropped, quarantined, packet_count, avg_packet_size, unique_dst_ports, unique_dst_ips,
//   z_packet_count, z_avg_packet_size, z_unique_dst_ports, z_unique_dst_ips,
//   alert (0/1), triggered_features ('+'-separated), baseline_action, consecutive_alerts
// z columns: a number, "warmup", "na" (inconclusive: near-zero variance), or empty (window not scored).
class TraceWriter {
public:
    bool open(const std::string& path, const std::vector<std::string>& headerMeta);
    bool isOpen() const { return out_.is_open(); }
    void write(const WindowResult& r);
    void finish(const PipelineCounters& c, const std::string& runStatus);

private:
    std::ofstream out_;
};

} // namespace netsentinel
