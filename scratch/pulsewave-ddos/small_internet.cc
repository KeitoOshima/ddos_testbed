#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/point-to-point-net-device.h"
#include "ns3/applications-module.h"
#include <sstream>
#include "ns3/internet-apps-module.h"
#include "ns3/csma-helper.h"
#include "ns3/tap-bridge-helper.h"
#include "ns3/nstime.h"
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <set>
#include <filesystem>
#include "experiment-config-reader.h"
#include "attack-schedule-helper.h"

#include "onoff-retarget-helper.h"
#include "onoff-retarget-application.h"
#include "ns3/inet-socket-address.h"
#include "ns3/ipv4-raw-socket-factory.h"

#include "ns3/boolean.h"
#include "ns3/data-rate.h"
#include "ns3/string.h"

#include <stdexcept>
#include <algorithm>

using namespace ns3;
namespace fs = std::filesystem;


struct NeighborInfo {
    uint32_t asn;
    std::string relationship;
};

struct InterfacesInfo {
    uint32_t interfaceId;
    Ipv4Address address;
    Ipv4Mask mask;
};

struct ASPrefixInfo {
    Ipv4Address network;
    Ipv4Mask mask;
};

struct PrefixAllocationState
{
    size_t prefixIndex = 0;
    uint32_t offset = 8;
};

std::string targetdir = "./ASrouteInfo";


std::vector<Ptr<Node>> ResolveNodes(
    const std::vector<NodeConfig>& configs,
    const std::map<uint32_t, Ptr<Node>>& asNodes)
{
    std::vector<Ptr<Node>> nodes;

    for (const auto& config : configs)
    {
        uint32_t asn = std::stoul(config.asNumber.substr(2));
        nodes.push_back(asNodes.at(asn));
    }

    return nodes;
}

std::map<uint32_t, std::vector<NeighborInfo>> ReadTopologyFromFile(const std::string& filename) {
    std::map<uint32_t, std::vector<NeighborInfo>> as_relation;
    std::ifstream relation_file(filename);
    if (!relation_file.is_open()) {
        std::cerr << "Failed to open topology file: " << filename << std::endl;
        return as_relation;
    }

    std::string line;
    while (std::getline(relation_file, line)) {
        if (line.empty() || line[0] == '#') {
            continue; 
        }

        size_t colon_pos = line.find(':');
        if (colon_pos == std::string::npos) {
            continue;
        }

        std::string aspart = line.substr(0, colon_pos);
        uint32_t asn = std::stoul(aspart.substr(2));

        std::string neighbors_part = line.substr(colon_pos + 1);

        std::istringstream iss(neighbors_part);
        std::string token;

        while (iss >> token) {
            size_t opneParen_pos = token.find('(');
            size_t closeParen_pos = token.find(')');

            if (opneParen_pos == std::string::npos || closeParen_pos == std::string::npos) {
                continue;
            }

            uint32_t neighbor_asn = std::stoul(token.substr(2, opneParen_pos - 2));

            std::string relationship = token.substr(opneParen_pos + 1, closeParen_pos - opneParen_pos - 1);
            as_relation[asn].push_back({neighbor_asn, relationship});
        }
    }
    return as_relation;
}


std::map<uint32_t, std::vector<ASPrefixInfo>> ReadASPrefixes(const std::string& filename){
    std::map<uint32_t, std::vector<ASPrefixInfo>> prefixes; 

    std::ifstream file(filename);

    if (!file.is_open()) {
        std::cerr
            << "Failed to open "
            << filename
            << std::endl;

        return prefixes;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) {
            continue;
        }

        size_t spacepos = line.find(' ');
        size_t slashpos = line.find('/');

        if (spacepos == std::string::npos || slashpos == std::string::npos) {
            continue;
        }

        try{
            uint32_t asn = std::stoul(line.substr(0, spacepos));

            std::string ippart = line.substr(spacepos + 1, slashpos - spacepos - 1);
            std::string prefix_length = line.substr(slashpos + 1);

            Ipv4Address ip(ippart.c_str());

            std::string maskpart = "/" + prefix_length;
            Ipv4Mask mask(maskpart.c_str());

            Ipv4Address network = ip.CombineMask(mask);


            prefixes[asn].push_back({network, mask});
        }
        catch (const std::exception& e) {
            std::cerr
            << "Failed to parse announcement: "
            << line
            << std::endl;
        }
    }
    return prefixes;
}


bool Allocate_Address_FromASprefix(uint32_t ownerAsn, const std::map<uint32_t, std::vector<ASPrefixInfo>>& asLinkPrefixes, std::map<uint32_t, PrefixAllocationState>& allocationStates, Ipv4Address& address1, Ipv4Address& address2) {
   
    auto prefixIt = asLinkPrefixes.find(ownerAsn);
    if (prefixIt == asLinkPrefixes.end()) {
        std::cerr
            << "No announced prefix for AS"
            << ownerAsn
            << std::endl;

        return false;
    }

    const std::vector<ASPrefixInfo>& prefixes = prefixIt->second;

    PrefixAllocationState& state = allocationStates[ownerAsn];

    while (state.prefixIndex < prefixes.size()) {
        const ASPrefixInfo& prefix = prefixes[state.prefixIndex];

        uint32_t prefixLength = prefix.mask.GetPrefixLength();
        if (prefixLength > 31) {
            state.prefixIndex++;
            state.offset = 8;
            continue;
        }

        uint64_t addressCount = 1ULL << (32 - prefixLength);

        // このprefix内にまだ2アドレス残っている
        if (static_cast<uint64_t>(state.offset) + 1 < addressCount)
        {
            uint32_t base = prefix.network.Get();

            address1 = Ipv4Address(base + state.offset);

            address2 = Ipv4Address(base + state.offset + 1);

            state.offset += 2;

            return true;
        }

        // std::cout
        // << "Prefix exhausted: AS"
        // << ownerAsn
        // << " prefix="
        // << prefix.network
        // << "/"
        // << prefixLength
        // << ", move to next prefix"
        // << std::endl;

        state.prefixIndex++;
        state.offset = 8;


    }
    // std::cerr
    // << "All link prefixes exhausted for AS"
    // << ownerAsn
    // << std::endl;

    return false;
    

}

void routingTableGenerator(const fs::path& targetdir, const std::map<uint32_t, Ptr<Node>>& asNodes, const std::map<uint32_t, std::map<uint32_t, InterfacesInfo>>& asinterfaces) {
    if (!fs::exists(targetdir) || !fs::is_directory(targetdir)) {
        std::cerr << "Invalid target directory: " << targetdir << std::endl;
        return;
    }

    for (const auto& file : fs::directory_iterator(targetdir)) {
        if (!fs::is_regular_file(file.status())) {
            continue;
        }

        std::ifstream targetFile(file.path());
        if (!targetFile.is_open()) {
            std::cerr << "Failed to open target file: " << file.path() << std::endl;
            continue;
        }

        std::string line;

        std::string aspart = file.path().stem().string();
        uint32_t asn = std::stoul(aspart.substr(2));

        auto nodeIt = asNodes.find(asn);
        if (nodeIt == asNodes.end()) {
            std::cerr << "Warning: AS " << asn << " found in route files but not in topology. Skipping." << std::endl;
            continue;
        }

        Ptr<Ipv4> ipv4 = asNodes.at(asn)->GetObject<Ipv4>();
        
        Ipv4StaticRoutingHelper staticRoutingHelper;
        Ptr<Ipv4StaticRouting> node = staticRoutingHelper.GetStaticRouting(ipv4);

        while (std::getline(targetFile, line)) {
            if (line.empty() || line[0] == 'd') {
                continue; 
            }

            size_t first_comma_pos = line.find(',');
            std::string aspart = line.substr(0, first_comma_pos);
            
            uint32_t dst_asn = std::stoul(aspart);
            
            size_t second_comma_pos = line.find(',', first_comma_pos + 1);
            std::string ip_part = line.substr(first_comma_pos + 1, second_comma_pos - first_comma_pos - 1);
            Ipv4Address ipv4(ip_part.c_str());

            size_t third_comma_pos = line.find(',', second_comma_pos + 1);
            std::string mask_part = line.substr(second_comma_pos + 1, third_comma_pos - second_comma_pos - 1);
            Ipv4Mask mask(mask_part.c_str());

            std::string nexthop_part = line.substr(third_comma_pos + 1);
            uint32_t nexthop_asn = std::stoul(nexthop_part);

            node->AddNetworkRouteToFast(ipv4, mask, asinterfaces.at(nexthop_asn).at(asn).address, asinterfaces.at(asn).at(nexthop_asn).interfaceId);

        }

    }
}



void SetHostaddress(const uint32_t& asn, Ptr<Ipv4>& node, std::map<uint32_t, ASPrefixInfo>& asPrefixes) {
    std::string announcements_line;
    std::ifstream prefix_file("announcements_origin.txt");

    if (!prefix_file.is_open()) {
        std::cerr << "Failed to open annoouncements_origin.txt" << std::endl;
        return;
    }

    while (std::getline(prefix_file, announcements_line)) {
        if (announcements_line.empty() || announcements_line[0] == 'S') {
            continue;
        }

        size_t space_pos = announcements_line.find(' ');

        if (space_pos == std::string::npos) {
            std::cerr << "Invalid line: ["
                      << announcements_line
                      << "]"
                      << std::endl;
            continue;
        }

        std::string aspart =
            announcements_line.substr(0, space_pos);
    
        uint32_t fileAsn = std::stoul(aspart);

        if (fileAsn != asn) {
            continue;
        }

        // 数字以外が来たときの確認
        try {
            uint32_t fileAsn = std::stoul(aspart);

            if (asn != fileAsn) {
                continue;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "stoul failed: line=["
                      << announcements_line
                      << "] aspart=["
                      << aspart
                      << "]"
                      << std::endl;

            continue;
        }

        size_t slash_pos = announcements_line.find('/');

        if (slash_pos == std::string::npos) {
            std::cerr << "Invalid prefix line: ["
                      << announcements_line
                      << "]"
                      << std::endl;
            continue;
        }

        std::string myip_part = announcements_line.substr(space_pos + 1, slash_pos - space_pos - 1);

        Ipv4Address ipv4(myip_part.c_str());
        Ipv4Address hostipv4(ipv4.Get() + 1);

        std::string mymask_part = "/" + announcements_line.substr(slash_pos + 1);

        Ipv4Mask mask(mymask_part.c_str());

        node->AddAddress(0, Ipv4InterfaceAddress(hostipv4, Ipv4Mask("255.255.255.255")));

        asPrefixes[asn] = {
            ipv4,
            mask
        };

    }
}





void SetupTapConnections (const std::set<uint32_t>& tapnode, const std::map<uint32_t, Ptr<Node>>& asNodes, std::map<uint32_t, ASPrefixInfo>& asPrefixes) {
    
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(1)));

    for(uint32_t asn : tapnode) {
        auto it = asNodes.find(asn);
        if (it == asNodes.end()) {
            std::cerr
            << "Tap target AS does not exist: AS"
            << asn
            << std::endl;

            continue;
        }
        
        ASPrefixInfo prefix = asPrefixes.at(asn);
        Ipv4Address tapAddress(prefix.network.Get() + 2);

        Ptr<Node> node = asNodes.at(asn);
        Ptr<Node> tapNode = CreateObject<Node>();

        NodeContainer tapContainer;
        tapContainer.Add(tapNode);
        tapContainer.Add(node);

        NetDeviceContainer tapdevice = csma.Install(tapContainer);

        Ptr<Ipv4> asIpv4 = node->GetObject<Ipv4>();

        int32_t ifId = asIpv4->GetInterfaceForDevice(tapdevice.Get(1));
        if (ifId == -1) {
            ifId = asIpv4->AddInterface(tapdevice.Get(1));
        }

        asIpv4->AddAddress(ifId, Ipv4InterfaceAddress(tapAddress, prefix.mask));

        asIpv4->SetMetric(ifId, 1);
        asIpv4->SetUp(ifId);

        // 確実にコンテナ側にIPを割り当てるために/32のネットワークアドレスをルーティングテーブルに割り当てる
        Ipv4Address containerAddress(prefix.network.Get() + 3);
        Ipv4StaticRoutingHelper staticRoutingHelper;
        Ptr<Ipv4StaticRouting> staticRouting = staticRoutingHelper.GetStaticRouting(asIpv4);
        staticRouting->AddHostRouteTo(containerAddress, ifId);


        std::string tapName = "tap-as" + std::to_string(asn);
        TapBridgeHelper tapBridge;

        tapBridge.SetAttribute(
            "Mode",
            StringValue("UseBridge"));

        tapBridge.SetAttribute(
            "DeviceName",
            StringValue(tapName));

        tapBridge.Install(
            tapNode,
            tapdevice.Get(0));

        std::cout
        << "Tap connected: AS"
        << asn
        << " tap="
        << tapName
        << " AS-access-IP="
        << tapAddress
        << std::endl;

    }

}


Ptr<Node> CreateVictimServer(
    uint32_t victimAsn,
    const std::map<uint32_t, Ptr<Node>>& asNodes,
    const std::map<uint32_t, ASPrefixInfo>& asPrefixes)
{
    Ptr<Node> victim = asNodes.at(victimAsn);
    Ptr<Node> server = CreateObject<Node>();

    InternetStackHelper().Install(server);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("1ms"));

    NetDeviceContainer devices =
        p2p.Install(victim, server);



    p2p.EnablePcap(
    "victim-server-link-AS" + std::to_string(victimAsn),
    devices.Get(0));




    ASPrefixInfo prefix = asPrefixes.at(victimAsn);
    Ipv4Mask mask("255.255.255.248");

    Ipv4Address addresses[2] = {
        Ipv4Address(prefix.network.Get() + 2),
        Ipv4Address(prefix.network.Get() + 3)
    };

    Ptr<Node> nodes[2] = {victim, server};
    uint32_t serverIf[2];  // Server側のインタフェース番号

    for (int i = 0; i < 2; i++)
    {
        Ptr<Ipv4> ipv4 = nodes[i]->GetObject<Ipv4>();
        uint32_t interface = ipv4->AddInterface(devices.Get(i));

        ipv4->AddAddress(
            interface,
            Ipv4InterfaceAddress(addresses[i], mask));

        ipv4->SetUp(interface);
        serverIf[i] = interface;
    }


    // log
    std::cout << "Victim AS" << victimAsn
            << " gateway=" << addresses[0]
            << " server=" << addresses[1]
            << std::endl;



    Ptr<Ipv4> victimIpv4 = victim->GetObject<Ipv4>();

    Ipv4Address serverAddress(addresses[1]);

    std::cout << "Server IP: " << serverAddress << std::endl;

    std::cout << "IsDestinationAddress: "
            << victimIpv4->IsDestinationAddress(
                    serverAddress,
                    serverIf[0])
            << std::endl;


    for (uint32_t i = 0; i < victimIpv4->GetNInterfaces(); ++i)
    {
        for (uint32_t j = 0; j < victimIpv4->GetNAddresses(i); ++j)
        {
            auto addr = victimIpv4->GetAddress(i, j);

            if (addr.GetLocal() == addresses[1])
            {
                std::cout << "DUPLICATE IP interface=" << i
                        << " address=" << addr.GetLocal()
                        << std::endl;
            }
        }
    }

    // Serverから外部へ返信するための経路
    Ipv4StaticRoutingHelper helper;
    helper.GetStaticRouting(server->GetObject<Ipv4>())
        ->SetDefaultRoute(addresses[0], serverIf[1]);

    return server;
}



int main (int argc, char *argv[])
{
    // double simTime = 200.0;

    GlobalValue::Bind(
    "SimulatorImplementationType",
    StringValue("ns3::RealtimeSimulatorImpl"));

    GlobalValue::Bind(
    "ChecksumEnabled",
    BooleanValue(true));

    // Ipv4Address testDstAddress;
    // Ipv4Address testSrcAddress;

    auto as_relation = ReadTopologyFromFile("as_topology.txt");
    
    std::map<uint32_t, Ptr<Node>> asNodes;
    for (const auto& [asn, neighbors] : as_relation) {
      Ptr<Node> node = CreateObject<Node>();
      asNodes[asn] = node;
    }

    InternetStackHelper internet;
    for (const auto& [asn, node] : asNodes) {
        internet.Install(node);
    }

    CommandLine cmd;

    std::string configFile = "/home/k-oshima/internet_testbed/ns-3.46/scratch/pulsewave-ddos/config/pulsewave_config.yaml";
    cmd.AddValue("configFile", "Path to the configuration file", configFile);
    cmd.Parse(argc, argv);



    ExperimentConfig experiment = ExperimentConfigReader::Load(configFile);

    AttackScheduleHelper schedule(
        experiment.attack,
        static_cast<int>(experiment.targets.size())
    );

    std::cout << "Total cycle duration: "
            << schedule.GetTotalCycleDuration()
            << " s" << std::endl;

    for (size_t i = 0; i < experiment.attack.attackVectors.size(); ++i)
    {
        auto [onTime, offTime] =
            schedule.GetOnOffTime(static_cast<int>(i));

        std::cout
            << "Vector: " << experiment.attack.attackVectors[i].type
            << ", Start: " << schedule.GetStartTime(static_cast<int>(i))
            << ", ON: " << onTime
            << ", OFF: " << offTime
            << std::endl;
    }

    std::cout << "Simulation duration: "
          << experiment.simulationDuration << std::endl;

    std::cout << "Burst duration: "
            << experiment.attack.burstDuration << std::endl;

    std::cout << "Number of attackers: "
            << experiment.attackers.size() << std::endl;

    std::cout << "Number of targets: "
            << experiment.targets.size() << std::endl;


    auto attackerNodes = ResolveNodes(experiment.attackers, asNodes);
    auto targetNodes = ResolveNodes(experiment.targets, asNodes);

    
    // 攻撃者ノードの確認
    std::cout << "=== Attackers ===" << std::endl;

    for (size_t i = 0; i < attackerNodes.size(); ++i)
    {
        std::cout
            << experiment.attackers[i].networkAddress
            << " (" << experiment.attackers[i].asNumber << ")"
            << " -> Node ID: " << attackerNodes[i]->GetId()
            << std::endl;
    }

    // 被害者ノードの確認
    std::cout << "=== Targets ===" << std::endl;

    for (size_t i = 0; i < targetNodes.size(); ++i)
    {
        std::cout
            << experiment.targets[i].networkAddress
            << " (" << experiment.targets[i].asNumber << ")"
            << " -> Node ID: " << targetNodes[i]->GetId()
            << std::endl;
    }


    PointToPointHelper p2p;
    p2p.SetDeviceAttribute ("DataRate", StringValue ("100Mbps"));
    p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));

    std::set<std::pair<uint32_t, uint32_t>> createdLinks;
    std::map<uint32_t, std::map<uint32_t, InterfacesInfo>> asinterfaces;
    std::map<uint32_t, ASPrefixInfo> asPrefixes;
    std::map<uint32_t, PrefixAllocationState> allocationStates;

    ns3::Ipv4AddressHelper ipv4;
    std::map<uint32_t, std::vector<ASPrefixInfo>> asLinkPrefixes = ReadASPrefixes("link_prefixes.txt");

    Ipv4Mask linkMask("255.255.255.254");
    std::set<uint32_t> tapnode {
        10010,
        4755,
        38091
    };



  for (const auto& [asn, neighbors] : as_relation) {

      for (const auto& neighbor : neighbors) {
            uint32_t neighbor_asn = neighbor.asn;
            std::string neighbor_relation = neighbor.relationship;
    
            uint32_t large_asn = std::max(asn, neighbor_asn);
            uint32_t small_asn = std::min(asn, neighbor_asn);

            std::pair<uint32_t, uint32_t> link_pair = {small_asn, large_asn};

            if (createdLinks.find(link_pair) != createdLinks.end()) {
                continue;
            }


            uint32_t prefixOwnerAsn;

            if (neighbor_relation == "provider") {
                // neighbor側がProvider
                prefixOwnerAsn =
                    neighbor_asn;
            }
            else if (neighbor_relation == "customer") {
                // asn側がProvider
                prefixOwnerAsn =
                    asn;
            }
            else if (neighbor_relation == "peer") {
                // PeerならASNの小さい方
                prefixOwnerAsn =
                    std::min(asn, neighbor_asn);
            }
            else {
                std::cerr
                    << "Unknown relationship: "
                    << neighbor_relation
                    << std::endl;

                continue;
            }

            Ipv4Address address1;
            Ipv4Address address2;

            if (!Allocate_Address_FromASprefix(prefixOwnerAsn, asLinkPrefixes, allocationStates, address1, address2))
            {
                if (prefixOwnerAsn == asn) {
                    prefixOwnerAsn = neighbor_asn;
                }else{
                    prefixOwnerAsn = asn;
                }

                if (!Allocate_Address_FromASprefix(prefixOwnerAsn, asLinkPrefixes, allocationStates, address1, address2)) {
                    std::cerr
                    << "Failed to allocate IP: AS"
                    << asn
                    << " <-> AS"
                    << neighbor_asn
                    << std::endl;

                    return 1;
                }
            }
            
            Ptr<Node> node1 = asNodes[asn];
            Ptr<Node> node2 = asNodes[neighbor_asn];

            NodeContainer link(node1, node2);
            NetDeviceContainer devices = p2p.Install(link);

            createdLinks.insert(link_pair);

            // assignメソッドを使わず、自分で実装 (AssignはIPの重複確認の処理が入っているが、時間がかかるので不採用)
            // Ipv4InterfaceContainer interfaces = ipv4.Assign(devices);

            Ptr<Ipv4> ipv4Node1 = node1->GetObject<Ipv4>();
            Ptr<Ipv4> ipv4Node2 = node2->GetObject<Ipv4>();

            int32_t if1 = ipv4Node1->GetInterfaceForDevice(devices.Get(0));
            if (if1 == -1) {
                if1 = ipv4Node1->AddInterface(devices.Get(0));
            }

            int32_t if2 = ipv4Node2->GetInterfaceForDevice(devices.Get(1));
            if (if2 == -1) {
                if2 = ipv4Node2->AddInterface(devices.Get(1));
            }


            // std::cout
            // << "LINK AS" << asn
            // << " <-> AS" << neighbor_asn
            // << " : "
            // << address1
            // << " <-> "
            // << address2
            // << " owner=AS"
            // << prefixOwnerAsn
            // << std::endl;

            ipv4Node1->AddAddress(if1, Ipv4InterfaceAddress(address1, linkMask));
            ipv4Node2->AddAddress(if2, Ipv4InterfaceAddress(address2, linkMask));

            ipv4Node1->SetMetric(if1, 1);
            ipv4Node2->SetMetric(if2, 1);

            ipv4Node1->SetUp(if1);
            ipv4Node2->SetUp(if2);

            asinterfaces[asn][neighbor_asn] = {if1, address1, linkMask};
            asinterfaces[neighbor_asn][asn] = {if2, address2, linkMask};
        }


    }

    std::cout << "finish creating links" << std::endl;

    for (const auto& [asn, node] : asNodes)
    {
        Ptr<Ipv4> ipv4Node = node->GetObject<Ipv4>();
        SetHostaddress(asn, ipv4Node, asPrefixes);
        
    }
    std::cout << "finish setting hostaddress" << std::endl;

    std::vector<Ptr<Node>> victimServers;

    for (const auto& target : experiment.targets)
    {
        uint32_t victimAsn = std::stoul(target.asNumber.substr(2));

        Ptr<Node> server =
            CreateVictimServer(victimAsn, asNodes, asPrefixes);

        victimServers.push_back(server);
    }


    routingTableGenerator(targetdir, asNodes, asinterfaces);

    Ipv4StaticRoutingHelper helper;

    SetupTapConnections(tapnode, asNodes, asPrefixes);

    std::cout << "finish setting routing tables" << std::endl;


    const double burst = experiment.attack.burstDuration;
    const double switchDuration = experiment.attack.targetSwitchDuration;
    const double cycleDuration = schedule.GetTotalCycleDuration();

    for (Ptr<Node> attacker : attackerNodes)
    {
        for (size_t vectorIndex = 0;
            vectorIndex < experiment.attack.attackVectors.size();
            ++vectorIndex)
        {
            const auto& vector = experiment.attack.attackVectors[vectorIndex];

            int protocol;
            AttackVector attackVector;

            if (vector.type == "udp_flooding")
            {
                protocol = 17;
                attackVector = AttackVector::udp_flooding;
            }
            else if (vector.type == "icmp_flooding")
            {
                protocol = 1;
                attackVector = AttackVector::icmp_flooding;
            }
            else if (vector.type == "tcp_syn_flooding")
            {
                protocol = 6;
                attackVector = AttackVector::tcp_syn_flooding;
            }
            else
            {
                throw std::runtime_error("Unknown attack vector: " + vector.type);
            }

            for (size_t targetIndex = 0;
                targetIndex < experiment.targets.size();
                ++targetIndex)
            {
                Ipv4Address targetIp(
                    experiment.targets[targetIndex].networkAddress.c_str());

                for (double cycleStart = 0.0;
                    cycleStart < experiment.simulationDuration;
                    cycleStart += cycleDuration)
                {
                    double startTime =
                        cycleStart +
                        schedule.GetStartTime(vectorIndex) +
                        targetIndex * (burst + switchDuration);

                    double stopTime = startTime + burst;

                    if (startTime >= experiment.simulationDuration)
                    {
                        break;
                    }

                    OnOffRetargetHelper attackHelper(
                        "ns3::Ipv4RawSocketFactory",
                        InetSocketAddress(targetIp, 0));

                    attackHelper.SetAttribute(
                        "RawProtocol", IntegerValue(protocol));

                    attackHelper.SetAttribute(
                        "AttackVector", IntegerValue(attackVector));

                    attackHelper.SetAttribute(
                        "SkipFirstOffTime", BooleanValue(true));

                    // アプリケーション実行中は送信を継続
                    attackHelper.SetAttribute(
                        "OnTime",
                        StringValue(
                            "ns3::ConstantRandomVariable[Constant=" +
                            std::to_string(burst + 1.0) + "]"));

                    attackHelper.SetAttribute(
                        "OffTime",
                        StringValue("ns3::ConstantRandomVariable[Constant=0]"));

                    uint32_t packetSize =
                        vector.type == "tcp_syn_flooding" ? 42 : vector.packetSize;

                    attackHelper.SetAttribute(
                        "DataRate",
                        DataRateValue(DataRate(vector.dataRate)));

                    attackHelper.SetAttribute(
                        "PacketSize",
                        UintegerValue(packetSize));

                    ApplicationContainer apps = attackHelper.Install(attacker);

                    apps.Start(Seconds(startTime));
                    apps.Stop(Seconds(std::min(
                        stopTime,
                        experiment.simulationDuration)));
                }
            }
        }
    }

    // pcapを取得する場所（AS番号, Device ID）
    std::vector<std::pair<uint32_t, uint32_t>> capturePoints = {
        {6507, asinterfaces.at(6507).at(9304).interfaceId},
        {6507, asinterfaces.at(6507).at(7473).interfaceId},
        {6507, asinterfaces.at(6507).at(2914).interfaceId},
        {6507, asinterfaces.at(6507).at(1299).interfaceId},
        {6507, asinterfaces.at(6507).at(45899).interfaceId},
        {48185, asinterfaces.at(48185).at(3356).interfaceId},
        {48185, asinterfaces.at(48185).at(9299).interfaceId},
        {48185, asinterfaces.at(48185).at(2914).interfaceId},
        {48185, asinterfaces.at(48185).at(1299).interfaceId},
        {48185, asinterfaces.at(48185).at(31133).interfaceId},
        {9304, asinterfaces.at(9304).at(15401).interfaceId},
        {2914, asinterfaces.at(2914).at(668).interfaceId},
        {668, asinterfaces.at(668).at(228).interfaceId},        
        
    };

    // 指定箇所でpcap取得
    for (const auto& [asn, deviceIndex] : capturePoints)
    {
        Ptr<Node> node = asNodes.at(asn);

        NS_ABORT_MSG_IF(
            deviceIndex >= node->GetNDevices(),
            "Invalid device index: AS" << asn << ", Device " << deviceIndex);

        Ptr<PointToPointNetDevice> dev =
            DynamicCast<PointToPointNetDevice>(
                node->GetDevice(deviceIndex));

        NS_ABORT_MSG_IF(
            !dev,
            "Not a PointToPoint device: AS" << asn << ", Device " << deviceIndex);

        p2p.EnablePcap("target-AS" + std::to_string(asn), dev);

        std::cout << "PCAP: AS" << asn
                << ", Device " << deviceIndex << std::endl;
    }

    for (size_t i = 0; i < victimServers.size(); ++i)
    {
        Ptr<Node> server = victimServers[i];

        std::cout << "Server AS"
                << experiment.targets[i].asNumber
                << " Node ID: " << server->GetId()
                << std::endl;

        for (uint32_t j = 0; j < server->GetNDevices(); ++j)
        {
            Ptr<NetDevice> dev = server->GetDevice(j);

            std::cout << "  Device " << j
                    << ": " << dev->GetInstanceTypeId().GetName()
                    << std::endl;

            if (DynamicCast<PointToPointNetDevice>(dev))
            {
                p2p.EnablePcap(
                    "server-" + experiment.targets[i].asNumber,
                    dev);
            }
        }
    }    

    // pcap出力
    // p2p.EnablePcapAll("as-topology");

    Simulator::Stop(Seconds(experiment.simulationDuration));

    std::cout << "Starting simulation..." << std::endl;
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
