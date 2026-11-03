// NetSentinel -- statistical network anomaly detection on PCAP files.
//
// Pipeline: PCAP -> FeatureExtractor -> Pipeline (time policy, 5 s tumbling windows, four
// Welford baselines, z-score scorer) -> console output.
// The per-packet loop lives in Pipeline (src/Pipeline.cpp); see that file for the time,
// idle-window and partial-window policies.

#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "ConsoleAlertEmitter.hpp"
#include "FeatureExtractor.hpp"
#include "PcapFileCapture.hpp"
#include "Pipeline.hpp"
#include "TraceWriter.hpp"

using namespace netsentinel;

namespace {

void printWindowHeader(const WindowResult& r) {
    const WindowFeatures& w = r.features;
    std::cout << "Window " << r.index << " [" << std::fixed << std::setprecision(1) << w.window_start_sec
              << "s - " << w.window_end_sec << "s)" << std::defaultfloat << std::setprecision(6);
}

void printWindow(const WindowResult& r, ConsoleAlertEmitter& emitter) {
    const WindowFeatures& w = r.features;
    printWindowHeader(r);
    switch (r.status) {
        case WindowStatus::Idle:
            std::cout << ": idle (no packets) -- not scored, not learned\n";
            return;
        case WindowStatus::NoParsedTraffic:
            std::cout << ": no parsed IPv4 traffic (" << w.raw_packet_count
                      << " packet(s) skipped) -- not scored, not learned\n";
            return;
        case WindowStatus::Partial:
            std::cout << ": partial final window (packet_count=" << w.packet_count
                      << ") -- not scored, not learned\n";
            return;
        case WindowStatus::Scored:
            break;
    }
    std::cout << ": packet_count=" << w.packet_count << " avg_packet_size=" << w.avg_packet_size_bytes
              << " unique_dst_ports=" << w.unique_dst_ports << " unique_dst_ips=" << w.unique_dst_ips << "\n";
    for (int k = 0; k < FEATURE_COUNT; ++k) {
        std::cout << "    " << FEATURE_NAMES[k] << ": ";
        switch (r.zState[k]) {
            case ZState::Warmup: std::cout << "warming up\n"; break;
            case ZState::NotAvailable: std::cout << "z=N/A (near-zero baseline variance)\n"; break;
            case ZState::Value: std::cout << "z=" << r.z[k] << "\n"; break;
            case ZState::NotScored: std::cout << "not scored\n"; break;
        }
    }
    if (r.alert) {
        emitter.emit(*r.alert);
    }
}

constexpr int EXIT_USAGE = 64;

const char* USAGE =
    "usage: netsentinel [options] [file.pcap]        (default file: data/sample.pcap)\n"
    "  --threshold T      absolute z-score threshold (default 3.0)\n"
    "  --gap-cap SEC      idle-gap cap and far-future threshold in seconds (default 60)\n"
    "  --trace PATH       write a per-window CSV trace (netsentinel-trace-v1) to PATH\n"
    "  --quiet            print only alerts and the run summary (not every window)\n"
    "  --policy P         baseline update policy: cumulative (original, default), gated, frozen (fixed comparator)\n"
    "  --recovery N       gated only: resume learning after N consecutive gated alerting windows (default 60)\n"
    "  --sd-floor         gated only: use the per-feature minimum standard deviation (SD floor)\n"
    "  --floor-values a,b,c,d   override the four floors (packet_count, avg_packet_size, unique_dst_ports,\n"
    "                     unique_dst_ips); implies nothing unless --sd-floor is given\n"
    "  --help             show this text\n"
    "exit codes: 0 ok, 1 cannot open / unsupported link type, 2 PCAP read error (results incomplete),\n"
    "            64 invalid command line\n";

struct Options {
    std::string pcapPath = "data/sample.pcap";
    PipelineConfig config;
    std::string tracePath;
    bool quiet = false;
};

bool parseDouble(const std::string& s, double& out) {
    char* end = nullptr;
    out = std::strtod(s.c_str(), &end);
    return end != s.c_str() && *end == '\0' && std::isfinite(out);
}

// Returns -1 to continue, otherwise the exit code.
int parseArgs(int argc, char** argv, Options& o) {
    bool havePath = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto value = [&](std::string& v) -> bool {
            if (i + 1 >= argc) return false;
            v = argv[++i];
            return true;
        };
        std::string v;
        if (a == "--help" || a == "-h") {
            std::cout << USAGE;
            return 0;
        } else if (a == "--quiet") {
            o.quiet = true;
        } else if (a == "--threshold") {
            if (!value(v) || !parseDouble(v, o.config.threshold) || o.config.threshold <= 0) {
                std::cerr << "invalid --threshold\n" << USAGE; return EXIT_USAGE;
            }
        } else if (a == "--gap-cap") {
            if (!value(v) || !parseDouble(v, o.config.gapCapSec) || o.config.gapCapSec < IWindowAggregator::WINDOW_LENGTH_SEC) {
                std::cerr << "invalid --gap-cap (must be >= 5)\n" << USAGE; return EXIT_USAGE;
            }
        } else if (a == "--policy") {
            if (!value(v)) { std::cerr << "--policy needs a value\n" << USAGE; return EXIT_USAGE; }
            // "b0" and "b1" are the legacy names, still accepted so that older commands keep working.
            if (v == "cumulative" || v == "b0") o.config.policy = BaselinePolicy::Cumulative;
            else if (v == "gated" || v == "b1") o.config.policy = BaselinePolicy::Gated;
            else if (v == "frozen") o.config.policy = BaselinePolicy::Frozen;
            else { std::cerr << "invalid --policy (cumulative, gated, frozen)\n" << USAGE; return EXIT_USAGE; }
        } else if (a == "--recovery") {
            double n = 0;
            if (!value(v) || !parseDouble(v, n) || n < 1 || n != std::floor(n) || n > 1e9) {
                std::cerr << "invalid --recovery (positive integer)\n" << USAGE; return EXIT_USAGE;
            }
            o.config.recoveryWindows = static_cast<int>(n);
        } else if (a == "--sd-floor") {
            o.config.sdFloorEnabled = true;
        } else if (a == "--floor-values") {
            if (!value(v)) { std::cerr << "--floor-values needs a,b,c,d\n" << USAGE; return EXIT_USAGE; }
            std::stringstream ss(v); std::string item; int k = 0;
            while (std::getline(ss, item, ',')) {
                double f = 0;
                if (k >= 4 || !parseDouble(item, f) || f <= 0) { k = -1; break; }
                o.config.sdFloor[static_cast<std::size_t>(k++)] = f;
            }
            if (k != 4) { std::cerr << "invalid --floor-values (four positive numbers)\n" << USAGE; return EXIT_USAGE; }
        } else if (a == "--trace") {
            if (!value(o.tracePath) || o.tracePath.empty()) { std::cerr << "--trace needs a path\n" << USAGE; return EXIT_USAGE; }
        } else if (!a.empty() && a[0] == '-') {
            std::cerr << "unknown option: " << a << "\n" << USAGE;
            return EXIT_USAGE;
        } else if (havePath) {
            std::cerr << "more than one input file given\n" << USAGE;
            return EXIT_USAGE;
        } else {
            o.pcapPath = a;
            havePath = true;
        }
    }
    if (o.config.sdFloorEnabled && o.config.policy != BaselinePolicy::Gated) {
        std::cerr << "--sd-floor applies to --policy gated only; the cumulative baseline stays unchanged\n" << USAGE;
        return EXIT_USAGE;
    }
    return -1;
}

std::string fmt(double v) {
    std::ostringstream os;
    os << v;
    return os.str();
}

} // namespace

int main(int argc, char** argv) {
    Options opt;
    const int parsed = parseArgs(argc, argv, opt);
    if (parsed >= 0) {
        return parsed;
    }
    const std::string& pcapPath = opt.pcapPath;

    std::cout << "NetSentinel -- Statistical Anomaly Detection Pipeline\n";
    std::cout << "Reading: " << pcapPath << "\n";
    if (opt.config.policy != BaselinePolicy::Cumulative) {
        std::cout << "Baseline policy: " << baselinePolicyName(opt.config.policy);
        if (opt.config.policy == BaselinePolicy::Gated) {
            std::cout << " (recovery after " << opt.config.recoveryWindows << " consecutive alerting windows, SD floor "
                      << (opt.config.sdFloorEnabled ? "on" : "off") << ")";
        }
        std::cout << "\n";
    }
    std::cout << "\n";

    PcapFileCapture capture;
    if (!capture.open(pcapPath)) {
        std::cerr << "Failed to open PCAP file: " << pcapPath << " (" << capture.lastError() << ")\n";
        return 1;
    }

    // Refuse link types the parser does not understand instead of silently parsing
    // nothing (the audit's linux_sll/vlan fixtures used to give 0 parsed packets and exit 0).
    const int linkType = capture.linkType();
    if (!FeatureExtractor::isSupportedLinkType(linkType)) {
        std::cerr << "Unsupported PCAP link type " << linkType
                  << " (supported: 1 = Ethernet incl. 802.1Q VLAN, 113 = Linux cooked capture)\n";
        return 1;
    }
    FeatureExtractor extractor(linkType);
    ConsoleAlertEmitter emitter;

    TraceWriter trace;
    if (!opt.tracePath.empty()) {
        const std::vector<std::string> meta = {
            "input=" + pcapPath, "window_sec=" + fmt(IWindowAggregator::WINDOW_LENGTH_SEC),
            "warmup_windows=" + std::to_string(IStatEngine::WARMUP_WINDOW_COUNT),
            "threshold=" + fmt(opt.config.threshold), "gap_cap_sec=" + fmt(opt.config.gapCapSec),
            std::string("policy=") + baselinePolicyName(opt.config.policy),
            "recovery_windows=" + std::to_string(opt.config.recoveryWindows),
            std::string("sd_floor=") + (opt.config.sdFloorEnabled ? "on" : "off"),
            "sd_floor_values=" + fmt(opt.config.sdFloor[0]) + "," + fmt(opt.config.sdFloor[1]) + "," +
                fmt(opt.config.sdFloor[2]) + "," + fmt(opt.config.sdFloor[3])};
        if (!trace.open(opt.tracePath, meta)) {
            std::cerr << "cannot write trace file: " << opt.tracePath << "\n";
            return 1;
        }
    }

    Pipeline pipeline(opt.config, [&](const WindowResult& r) {
        if (!opt.quiet) {
            printWindow(r, emitter);
        } else if (r.alert) {
            printWindowHeader(r);
            std::cout << "\n";
            emitter.emit(*r.alert);
        }
        trace.write(r);
    });

    while (auto raw = capture.next()) {
        const auto feature = extractor.extract(*raw);
        pipeline.onPacket(raw->capture_timestamp_sec, feature, extractor.lastSkipReason());
    }
    pipeline.finish();
    capture.close();

    const PipelineCounters& c = pipeline.counters();
    trace.finish(c, capture.hadError() ? "read_error" : "clean_eof");
    std::cout << "\n--- Run summary ---\n";
    std::cout << "Packets read from PCAP:                 " << c.packetsRead << "\n";
    std::cout << "Packets parsed (IPv4):                  " << c.packetsParsed << "\n";
    std::cout << "Packets skipped (unparseable/non-IPv4):  " << c.packetsSkipped() << "\n";
    std::cout << "  of which IPv6:                        " << c.skippedIpv6 << "\n";
    std::cout << "  of which other ethertype:             " << c.skippedOtherEthertype << "\n";
    std::cout << "  of which malformed IPv4:              " << c.skippedMalformedIpv4 << "\n";
    std::cout << "  of which truncated link header:       " << c.skippedTruncatedLink << "\n";
    std::cout << "Late packets dropped:                   " << c.lateDropped << "\n";
    std::cout << "Far-future packets quarantined:         " << c.quarantined << "\n";
    std::cout << "Idle gaps capped (60 s rule):           " << c.gapCaps << "\n";
    std::cout << "Windows emitted:                        " << c.windowsEmitted << "\n";
    std::cout << "  scored:                               " << c.windowsScored << "\n";
    std::cout << "  idle (not scored/learned):            " << c.windowsIdle << "\n";
    std::cout << "  no parsed traffic (not scored/learned): " << c.windowsNoParsedTraffic << "\n";
    std::cout << "  partial final (not scored/learned):   " << c.windowsPartial << "\n";
    std::cout << "Alerts raised:                           " << c.alerts << "\n";
    if (opt.config.policy != BaselinePolicy::Cumulative) {
        std::cout << "Baseline policy:                        " << baselinePolicyName(opt.config.policy) << "\n";
    }

    // A PCAP READ ERROR (e.g. truncated file) is not a clean end of file.
    if (capture.hadError()) {
        std::cerr << "PCAP read error after " << c.packetsRead << " packet(s): " << capture.lastError()
                  << " -- results above are incomplete\n";
        return 2;
    }
    return 0;
}
