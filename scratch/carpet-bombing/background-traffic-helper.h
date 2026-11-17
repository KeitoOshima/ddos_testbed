#ifndef BACKGROUND_TRAFFIC_HELPER_H
#define BACKGROUND_TRAFFIC_HELPER_H

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"

#include <cstdint>
#include <map>
#include <string>

namespace ns3 {
namespace background {

struct Options {
    std::string csvFile = "ns3_background.csv";
    uint16_t port = 50000;
    uint32_t packetSize = 1000;
    double startTime = 1.0;
    double stopTime = 600.0;
    // 0 = no limit; rows are taken in file order (not a random sample).
    uint64_t maxFlows = 0;
    uint32_t seed = 20261116;
    uint32_t victimAsn = 12975;
    uint32_t victimTargetOffset = 8;
    uint32_t victimTargetCount = 1024;
};

struct Stats {
    uint64_t scanned = 0;
    uint64_t installed = 0;
    uint64_t skippedZeroRate = 0;
    uint64_t sinks = 0;
    long double requestedRateBps = 0;
};

Stats Install(
    const Options& opt,
    const std::map<uint32_t, Ptr<Node>>& asNodes,
    const std::map<uint32_t, Ipv4Address>& hostAddresses,
    const std::map<uint32_t, Ptr<Node>>& victimServers,
    const std::map<uint32_t, Ipv4Address>& victimNetworkAddresses);

} // namespace background
} // namespace ns3
#endif
