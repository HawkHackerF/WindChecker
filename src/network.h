#pragma once
#include "common.h"

struct NfatConfig {
    bool tcp = true;
    bool udp = true;
    bool dns = true;
    bool arp = true;
    bool adapters = true;
    bool traffic = true;
    bool full = true;
    double interval = 2.0;
    bool realtime = true;
};

struct NetSnapshot {
    std::vector<Row> rows;
    double inRate = 0.0;
    double outRate = 0.0;
};

class NetworkCollector {
public:
    explicit NetworkCollector(NfatConfig config) : config_(config) {}
    NetSnapshot Collect();

private:
    NfatConfig config_;
    std::vector<DnsEntry> dnsCache_;
    std::vector<ArpEntry> arpCache_;
    std::chrono::steady_clock::time_point heavyAt_{};
    std::chrono::steady_clock::time_point previousAt_{};
    std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> previousTraffic_;
};
