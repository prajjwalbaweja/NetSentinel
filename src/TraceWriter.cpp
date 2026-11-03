#include "TraceWriter.hpp"

#include <cmath>
#include <cstdio>

namespace netsentinel {

namespace {
std::string num(double v) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.10g", v);
    return buf;
}
} // namespace

bool TraceWriter::open(const std::string& path, const std::vector<std::string>& headerMeta) {
    out_.open(path, std::ios::out | std::ios::trunc);
    if (!out_.is_open()) {
        return false;
    }
    out_ << "# format=netsentinel-trace-v1\n";
    for (const auto& m : headerMeta) {
        out_ << "# " << m << "\n";
    }
    out_ << "window_index,window_start,window_end,status,raw_packets,parsed_packets,"
            "skipped_ipv6,skipped_other_ethertype,skipped_malformed_ipv4,skipped_truncated_link,"
            "late_dropped,quarantined,packet_count,avg_packet_size,unique_dst_ports,unique_dst_ips,"
            "z_packet_count,z_avg_packet_size,z_unique_dst_ports,z_unique_dst_ips,"
            "alert,triggered_features,baseline_action,consecutive_alerts\n";
    return true;
}

void TraceWriter::write(const WindowResult& r) {
    if (!out_.is_open()) {
        return;
    }
    const WindowFeatures& w = r.features;
    out_ << r.index << ',' << num(w.window_start_sec) << ',' << num(w.window_end_sec) << ','
         << windowStatusName(r.status) << ',' << w.raw_packet_count << ',' << w.packet_count << ','
         << w.skipped_ipv6 << ',' << w.skipped_other_ethertype << ',' << w.skipped_malformed_ipv4 << ','
         << w.skipped_truncated_link << ',' << w.late_dropped << ',' << w.quarantined << ','
         << w.packet_count << ',' << num(w.avg_packet_size_bytes) << ',' << w.unique_dst_ports << ','
         << w.unique_dst_ips;
    for (int k = 0; k < FEATURE_COUNT; ++k) {
        out_ << ',';
        switch (r.zState[k]) {
            case ZState::NotScored: break;
            case ZState::Warmup: out_ << "warmup"; break;
            case ZState::NotAvailable: out_ << "na"; break;
            case ZState::Value: out_ << num(r.z[k]); break;
        }
    }
    out_ << ',' << (r.alert ? 1 : 0) << ',';
    if (r.alert) {
        for (std::size_t i = 0; i < r.alert->triggered_features.size(); ++i) {
            out_ << (i ? "+" : "") << r.alert->triggered_features[i].feature_name;
        }
    }
    out_ << ',' << baselineActionName(r.action) << ',' << r.consecutiveAlerts << '\n';
}

void TraceWriter::finish(const PipelineCounters& c, const std::string& runStatus) {
    if (!out_.is_open()) {
        return;
    }
    out_ << "# run_status=" << runStatus << "\n"
         << "# packets_read=" << c.packetsRead << "\n"
         << "# packets_parsed=" << c.packetsParsed << "\n"
         << "# skipped_ipv6=" << c.skippedIpv6 << "\n"
         << "# skipped_other_ethertype=" << c.skippedOtherEthertype << "\n"
         << "# skipped_malformed_ipv4=" << c.skippedMalformedIpv4 << "\n"
         << "# skipped_truncated_link=" << c.skippedTruncatedLink << "\n"
         << "# late_dropped=" << c.lateDropped << "\n"
         << "# quarantined=" << c.quarantined << "\n"
         << "# gap_caps=" << c.gapCaps << "\n"
         << "# idle_windows_suppressed=" << c.idleWindowsSuppressed << "\n"
         << "# windows_emitted=" << c.windowsEmitted << "\n"
         << "# windows_scored=" << c.windowsScored << "\n"
         << "# windows_idle=" << c.windowsIdle << "\n"
         << "# windows_no_parsed_traffic=" << c.windowsNoParsedTraffic << "\n"
         << "# windows_partial=" << c.windowsPartial << "\n"
         << "# alerts=" << c.alerts << "\n";
    out_.flush();
}

} // namespace netsentinel
