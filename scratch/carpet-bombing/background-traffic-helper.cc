#include "variable-packet-udp-application.h"
#include "background-traffic-helper.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <limits>
#include <random>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace ns3 {
namespace background {

// Background traffic startup dispersion window (seconds).
// Each flow starts randomly within this window.
static constexpr double START_SPREAD_SECONDS = 5.0;

std::vector<std::string> SplitCsv(const std::string& line)
{
    std::vector<std::string> cols;
    std::stringstream ss(line);
    std::string col;

    while (std::getline(ss, col, ','))
    {
        cols.push_back(col);
    }

    return cols;
}

Stats Install(
    const Options& opt,
    const std::map<uint32_t, Ptr<Node>>& asNodes,
    const std::map<uint32_t, Ipv4Address>& hostAddresses,
    const std::map<uint32_t, Ptr<Node>>& victimServers,
    const std::map<uint32_t, Ipv4Address>& victimNetworkAddresses)
{
    NS_ABORT_MSG_IF(
        opt.stopTime <= opt.startTime,
        "Background stopTime must exceed startTime");

    NS_ABORT_MSG_IF(
        opt.packetSize == 0,
        "Background packetSize must be positive");

    NS_ABORT_MSG_IF(
        opt.victimTargetCount == 0,
        "Background victimTargetCount must be positive");

    std::ifstream in(opt.csvFile);

    NS_ABORT_MSG_IF(
        !in,
        "Cannot open background CSV: " << opt.csvFile);

    std::string header;

    NS_ABORT_MSG_IF(
        !std::getline(in, header),
        "Empty background CSV");

    auto names = SplitCsv(header);

    std::map<std::string, size_t> colIndex;

    for (size_t i = 0; i < names.size(); ++i)
    {
        if (!names[i].empty() && names[i].back() == '\r')
        {
            names[i].pop_back();
        }

        colIndex[names[i]] = i;
    }

    for (const char* required : {"src_as", "dst_as", "rate_bps"})
    {
        NS_ABORT_MSG_IF(
            colIndex.count(required) == 0,
            "Missing CSV column: " << required);
    }

    Stats stats;

    std::map<uint32_t, bool> installedSinks;

    std::mt19937 rng(opt.seed);

    // Separate RNG for startup timing to avoid changing
    // the existing victim target selection sequence.
    std::mt19937 startRng(opt.seed);

    std::uniform_int_distribution<uint32_t> targetDist(
        0,
        opt.victimTargetCount - 1);

    // Keep the start window strictly inside the application lifetime.
    const double startSpread = std::min(
        START_SPREAD_SECONDS,
        (opt.stopTime - opt.startTime) * 0.5);

    std::uniform_real_distribution<double> startDist(
        0.0,
        startSpread);

    std::string line;

    while (std::getline(in, line))
    {
        if (line.empty())
        {
            continue;
        }

        auto fields = SplitCsv(line);

        auto get = [&](const std::string& name) -> const std::string&
        {
            size_t index = colIndex.at(name);

            if (index >= fields.size())
            {
                throw std::runtime_error(
                    "Malformed CSV row " +
                    std::to_string(stats.scanned + 2));
            }

            return fields[index];
        };

        ++stats.scanned;

        // AS numbers
        uint32_t srcAs =
            static_cast<uint32_t>(std::stoul(get("src_as")));

        uint32_t dstAs =
            static_cast<uint32_t>(std::stoul(get("dst_as")));

        // Preserve fractional rates, including sub-1 bps.
        double rate = std::stod(get("rate_bps"));

        NS_ABORT_MSG_IF(
            !std::isfinite(rate) || rate < 0.0,
            "Invalid rate_bps at CSV line "
                << stats.scanned + 1);

        if (rate == 0.0)
        {
            ++stats.skippedZeroRate;
            continue;
        }

        // Find source AS node.
        auto srcIt = asNodes.find(srcAs);

        NS_ABORT_MSG_IF(
            srcIt == asNodes.end(),
            "Missing source AS " << srcAs);

        Ipv4Address destination;
        Ptr<Node> sinkNode;

        // Determine destination.
        if (dstAs == opt.victimAsn)
        {
            auto serverIt = victimServers.find(dstAs);
            auto networkIt = victimNetworkAddresses.find(dstAs);

            NS_ABORT_MSG_IF(
                serverIt == victimServers.end() ||
                networkIt == victimNetworkAddresses.end(),
                "Victim server/network missing for AS " << dstAs);

            sinkNode = serverIt->second;

            uint64_t addr =
                static_cast<uint64_t>(
                    networkIt->second.Get()) +
                opt.victimTargetOffset +
                targetDist(rng);

            NS_ABORT_MSG_IF(
                addr > std::numeric_limits<uint32_t>::max(),
                "Victim IP overflow");

            destination =
                Ipv4Address(static_cast<uint32_t>(addr));
        }
        else
        {
            auto dstIt = asNodes.find(dstAs);
            auto ipIt = hostAddresses.find(dstAs);

            NS_ABORT_MSG_IF(
                dstIt == asNodes.end() ||
                ipIt == hostAddresses.end(),
                "Missing destination node/IP for AS " << dstAs);

            sinkNode = dstIt->second;
            destination = ipIt->second;
        }

        // Install one UDP listener per destination AS.
        if (!installedSinks[dstAs])
        {
            PacketSinkHelper sinkHelper(
                "ns3::UdpSocketFactory",
                InetSocketAddress(
                    Ipv4Address::GetAny(),
                    opt.port));

            ApplicationContainer sink =
                sinkHelper.Install(sinkNode);

            sink.Start(Seconds(0.0));
            sink.Stop(Seconds(opt.stopTime));

            installedSinks[dstAs] = true;
            ++stats.sinks;
        }

        // Randomize the startup time for each flow.
        const double flowStartTime =
            opt.startTime + startDist(startRng);

        // Install background traffic application.
        if (opt.randomPacketSize)
        {
            // Variable packet size UDP application.
            // Keep the original fractional bit rate.
            Ptr<VariablePacketUdpApplication> app =
                CreateObject<VariablePacketUdpApplication>();

            app->Setup(
                InetSocketAddress(destination, opt.port),
                rate,
                opt.minPacketSize,
                opt.maxPacketSize);

            app->AssignStream(
                static_cast<int64_t>(stats.installed) + 1);

            srcIt->second->AddApplication(app);

            app->SetStartTime(Seconds(flowStartTime));
            app->SetStopTime(Seconds(opt.stopTime));
        }
        else
        {
            // Original fixed-size UDP implementation.
            // OnOffApplication uses an integer DataRate.
            NS_ABORT_MSG_IF(
                rate < 1.0 ||
                static_cast<long double>(rate) >=
                    std::ldexp(1.0L, 64),
                "Invalid rate for OnOffApplication");

            uint64_t integerRate =
                static_cast<uint64_t>(rate);

            OnOffHelper onoff(
                "ns3::UdpSocketFactory",
                InetSocketAddress(destination, opt.port));

            onoff.SetAttribute(
                "DataRate",
                DataRateValue(DataRate(integerRate)));

            onoff.SetAttribute(
                "PacketSize",
                UintegerValue(opt.packetSize));

            onoff.SetAttribute(
                "OnTime",
                StringValue(
                    "ns3::ConstantRandomVariable[Constant=1e9]"));

            onoff.SetAttribute(
                "OffTime",
                StringValue(
                    "ns3::ConstantRandomVariable[Constant=0]"));

            ApplicationContainer app =
                onoff.Install(srcIt->second);

            app.Start(Seconds(flowStartTime));
            app.Stop(Seconds(opt.stopTime));
        }

        ++stats.installed;

        stats.requestedRateBps += rate;

        if (opt.maxFlows != 0 &&
            stats.installed >= opt.maxFlows)
        {
            break;
        }
    }

    return stats;
}

} // namespace background
} // namespace ns3