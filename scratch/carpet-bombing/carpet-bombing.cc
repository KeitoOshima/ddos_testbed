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
#include <chrono>
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
#include "background-traffic-helper.h"

#include <stdexcept>
#include <algorithm>
#include <numeric>
#include <random>

using namespace ns3;
namespace fs = std::filesystem;


struct CarpetTargetScheduler
{
    Ipv4Address network;
    uint32_t offset = 8;
    uint32_t candidateCount = 1024;
    uint32_t activeCount = 256;

    double switchPeriod = 5.0;
    double stopTime = 0.0;

    // 再現性のため乱数シードを固定
    std::mt19937 rng{20261104};

    // [攻撃者][宛先スロット]
    std::vector<std::vector<Ptr<OnOffRetargetApplication>>> applications;

    std::ofstream log;
};


// 1024個の候補から256個を重複なしで選択
static std::vector<Ipv4Address> DrawCarpetTargets(CarpetTargetScheduler& scheduler)
{
    std::vector<uint32_t> indices(scheduler.candidateCount);

    std::iota(indices.begin(), indices.end(), 0);

    std::shuffle(
        indices.begin(),
        indices.end(),
        scheduler.rng);

    std::vector<Ipv4Address> selected;
    selected.reserve(scheduler.activeCount);

    for (uint32_t i = 0; i < scheduler.activeCount; ++i)
    {
        selected.emplace_back(scheduler.network.Get() + scheduler.offset + indices[i]);
    }

    return selected;
}


// 選択された宛先をCSVに記録
static void RecordCarpetTargets(CarpetTargetScheduler* scheduler, const std::vector<Ipv4Address>& selected)
{
    const double now = Simulator::Now().GetSeconds();

    for (uint32_t i = 0; i < selected.size(); ++i)
    {
        scheduler->log
            << now << ","
            << i << ","
            << selected[i]
            << "\n";
    }

    scheduler->log.flush();

    std::cout
        << "[CARPET SWITCH] t="
        << now
        << "s, activeTargets="
        << selected.size()
        << std::endl;
}


// 5秒ごとに宛先集合を更新
static void SwitchCarpetTargets(CarpetTargetScheduler* scheduler)
{
    auto selected = DrawCarpetTargets(*scheduler);

    // すべての攻撃者で同じ256宛先を使用
    for (const auto& attackerApps : scheduler->applications)
    {
        NS_ABORT_MSG_IF(attackerApps.size() != scheduler->activeCount, "Unexpected number of carpet-bombing applications");

        for (uint32_t i = 0; i < scheduler->activeCount; ++i)
        {
            attackerApps[i]->SetRemote(InetSocketAddress(selected[i], 0));
        }
    }

    RecordCarpetTargets(scheduler, selected);

    // 次の切り替えを予約
    const double next = Simulator::Now().GetSeconds() + scheduler->switchPeriod;

    if (next < scheduler->stopTime)
    {
        Simulator::Schedule(Seconds(scheduler->switchPeriod), &SwitchCarpetTargets, scheduler);
    }
}



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


std::vector<Ptr<Node>> ResolveNodes(const std::vector<NodeConfig>& configs, const std::map<uint32_t, Ptr<Node>>& asNodes)
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
    
    // 特定のAS番号とprefixIndex、offsetの組み合わせに対して、offsetを変更する処理
    if (ownerAsn == 12975 && state.prefixIndex == 0 && state.offset == 8)
    {
        state.offset = 1032; //1024個のアドレス空間＋8個のアドレス空間 (全ASで保持) をスキップする
    }

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

        tapBridge.SetAttribute("Mode", StringValue("UseBridge"));

        tapBridge.SetAttribute("DeviceName", StringValue(tapName));

        tapBridge.Install(tapNode, tapdevice.Get(0));

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


Ptr<Node> CreateVictimServer(uint32_t victimAsn, const std::map<uint32_t, Ptr<Node>>& asNodes, const std::map<uint32_t, ASPrefixInfo>& asPrefixes)
{
    Ptr<Node> victim = asNodes.at(victimAsn);
    Ptr<Node> server = CreateObject<Node>();

    InternetStackHelper().Install(server);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("10Gbps"));
    p2p.SetChannelAttribute("Delay", StringValue("10ms"));

    p2p.SetQueue(
        "ns3::DropTailQueue<Packet>",
        "MaxSize",
        StringValue("10000p")
    );
    
    NetDeviceContainer devices = p2p.Install(victim, server);

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
    uint32_t If[2];  // Server側のインタフェース番号

    for (int i = 0; i < 2; i++)
    {
        Ptr<Ipv4> ipv4 = nodes[i]->GetObject<Ipv4>();
        uint32_t interface = ipv4->AddInterface(devices.Get(i));

        ipv4->AddAddress(
            interface,
            Ipv4InterfaceAddress(addresses[i], mask));

        ipv4->SetUp(interface);
        If[i] = interface;
    }


    // Serverから外部へ返信するための経路
    Ipv4StaticRoutingHelper helper;
    helper.GetStaticRouting(server->GetObject<Ipv4>())
        ->SetDefaultRoute(addresses[0], If[1]);


    // ===== Carpet-bombing用の追加処理 =====

    const uint32_t targetCount = 1024;
    const uint32_t targetOffset = 8;

    Ptr<Ipv4> serverIpv4 = server->GetObject<Ipv4>();

    Ptr<Ipv4StaticRouting> victimRouting = helper.GetStaticRouting(victim->GetObject<Ipv4>());

    for (uint32_t i = 0; i < targetCount; ++i)
    {
        Ipv4Address targetIp(prefix.network.Get() + targetOffset + i);

        // 1. Serverに宛先IPを追加
        serverIpv4->AddAddress(
            If[1], Ipv4InterfaceAddress(targetIp, Ipv4Mask("255.255.255.255"))
        );

        // 2. Target ASルータにホスト経路を追加
        victimRouting->AddHostRouteTo(
            targetIp,
            addresses[1],
            If[0]
        );
    }

    std::cout
        << "[Carpet-bombing] Target AS" << victimAsn
        << ": assigned " << targetCount
        << " IP addresses to target server"
        << std::endl;

    return server;
}



int main (int argc, char *argv[])
{
    // GlobalValue::Bind(
    // "SimulatorImplementationType",
    // StringValue("ns3::RealtimeSimulatorImpl"));

    GlobalValue::Bind(
    "ChecksumEnabled",
    BooleanValue(true));

    auto as_relation = ReadTopologyFromFile("as_topology.txt");

    // 背景トラフィックがTCPのみコメントは外す
    // // TCPの送受信バッファを16 MiBに拡大
    // Config::SetDefault(
    //     "ns3::TcpSocket::SndBufSize",
    //     UintegerValue(16 * 1024 * 1024)
    // );

    // Config::SetDefault(
    //     "ns3::TcpSocket::RcvBufSize",
    //     UintegerValue(16 * 1024 * 1024)
    // );

    // // TCPのMSSを1460 bytesに変更
    // Config::SetDefault(
    //     "ns3::TcpSocket::SegmentSize",
    //     UintegerValue(1460)
    // );



    
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

    std::string configFile = "/home/k-oshima/internet_testbed/ns-3.46/scratch/carpet-bombing/config/carpet_config.yaml";
    cmd.AddValue("configFile", "Path to the configuration file", configFile);
    cmd.Parse(argc, argv);

    ExperimentConfig experiment = ExperimentConfigReader::Load(configFile);


    std::cout << "Simulation duration: "
          << experiment.simulationDuration << std::endl;

    std::cout << "Number of attackers: "
            << experiment.attackers.size() << std::endl;

    auto attackerNodes = ResolveNodes(experiment.attackers, asNodes);
    auto targetNodes = ResolveNodes(experiment.targets, asNodes);


    PointToPointHelper p2p;
    p2p.SetDeviceAttribute ("DataRate", StringValue ("10Gbps"));
    p2p.SetChannelAttribute ("Delay", StringValue ("10ms"));

    p2p.SetQueue(
        "ns3::DropTailQueue<Packet>",
        "MaxSize",
        StringValue("10000p")
    );

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

        Ptr<Node> server = CreateVictimServer(victimAsn, asNodes, asPrefixes);

        victimServers.push_back(server);
    }

    routingTableGenerator(targetdir, asNodes, asinterfaces);

    // SetupTapConnections(tapnode, asNodes, asPrefixes);

    std::cout << "finish setting routing tables" << std::endl;





    // ===== Background Traffic =====

    // AS番号 -> ホストIP
    std::map<uint32_t, Ipv4Address> hostAddresses;

    for (const auto& [asn, prefix] : asPrefixes)
    {
        hostAddresses.emplace(
            asn,
            Ipv4Address(prefix.network.Get() + 1)
        );
    }

    // 被害AS番号 -> Serverノード
    std::map<uint32_t, Ptr<Node>> backgroundVictimServers;

    // 被害AS番号 -> ネットワークアドレス
    std::map<uint32_t, Ipv4Address> victimNetworks;

    for (size_t i = 0; i < experiment.targets.size(); ++i)
    {
        uint32_t asn =
            std::stoul(experiment.targets[i].asNumber.substr(2));

        backgroundVictimServers.emplace(asn, victimServers.at(i));
        victimNetworks.emplace(asn, asPrefixes.at(asn).network);
    }

    // 背景通信の設定
    background::Options bg;

    bg.csvFile = "ns3_background.csv";
    bg.victimAsn = 12975;
    bg.victimTargetOffset = 8;
    bg.victimTargetCount = 1024;

    bg.port = 50000;
    bg.packetSize = 1000;

    bg.startTime = 1.0;
    bg.stopTime = experiment.simulationDuration;

    // テストCSVは10組
    bg.maxFlows = 0;

    // 背景通信の生成
    auto bgStats = background::Install(
        bg,
        asNodes,
        hostAddresses,
        backgroundVictimServers,
        victimNetworks
    );

    std::cout << "===== Background Traffic =====" << std::endl;
    std::cout << "Scanned: " << bgStats.scanned << std::endl;
    std::cout << "Installed: " << bgStats.installed << std::endl;
    std::cout << "Sinks: " << bgStats.sinks << std::endl;
    std::cout << "Requested rate: "
            << static_cast<double>(bgStats.requestedRateBps)
            << " bps" << std::endl;





    // ===== Attack traffic =====
    // Carpet-bombing: 固定256宛先へのTCP SYN送信
    // ===== NetRadar-style Carpet-bombing =====

    // const uint32_t simultaneousTargets = experiment.carpetBombing.simultaneousTargets;
    // const uint32_t candidateTargets = experiment.carpetBombing.candidateTargets;
    // const uint32_t targetOffset = experiment.carpetBombing.targetOffset;

    // // YAMLのCIDR表記からネットワークアドレスを取得
    // std::string prefix = experiment.carpetBombing.targetPrefix;
    // std::string networkAddress = prefix.substr(0, prefix.find('/'));
    // Ipv4Address targetNetwork(networkAddress.c_str());

    // // 各攻撃者ASの総送信レート
    // const uint64_t totalRateBps = experiment.carpetBombing.totalRateBps;

    // // 各宛先に均等分配
    // const uint64_t ratePerTarget = totalRateBps / simultaneousTargets;
    // const double attackStart = experiment.carpetBombing.attackStart;
    // const double targetSwitchPeriod = experiment.carpetBombing.targetSwitchDuration;

    // // ===== Scheduler初期化 =====

    // CarpetTargetScheduler carpetScheduler;

    // carpetScheduler.network = targetNetwork;
    // carpetScheduler.offset = targetOffset;
    // carpetScheduler.candidateCount = candidateTargets;
    // carpetScheduler.activeCount = simultaneousTargets;
    // carpetScheduler.switchPeriod = targetSwitchPeriod;
    // carpetScheduler.stopTime = experiment.simulationDuration;

    // carpetScheduler.log.open("carpet-target-selection.csv");

    // NS_ABORT_MSG_IF(!carpetScheduler.log.is_open(), "Cannot open target selection log");

    // carpetScheduler.log << "time_s,slot,target_ip\n";

    // // ===== 最初の256宛先を抽選 =====

    // auto initialTargets = DrawCarpetTargets(carpetScheduler);

    // carpetScheduler.applications.reserve(attackerNodes.size());


    // // ===== 攻撃アプリケーション生成 =====

    // for (Ptr<Node> attacker : attackerNodes)
    // {
    //     std::vector<Ptr<OnOffRetargetApplication>> attackerApps;

    //     attackerApps.reserve(simultaneousTargets);

    //     for (uint32_t targetIndex = 0; targetIndex < simultaneousTargets; ++targetIndex)
    //     {
    //         OnOffRetargetHelper attackHelper("ns3::Ipv4RawSocketFactory", InetSocketAddress(initialTargets[targetIndex], 0));

    //         attackHelper.SetAttribute("RawProtocol", IntegerValue(6));

    //         attackHelper.SetAttribute("AttackVector", IntegerValue(AttackVector::tcp_syn_flooding));

    //         attackHelper.SetAttribute("SkipFirstOffTime", BooleanValue(true));

    //         attackHelper.SetAttribute("SkipFirstScheduleAfterRemoteChange", BooleanValue(true));

    //         attackHelper.SetAttribute("OnTime",StringValue("ns3::ConstantRandomVariable[Constant=200.0]"));

    //         attackHelper.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    //         attackHelper.SetAttribute("DataRate", DataRateValue(DataRate(ratePerTarget)));

    //         attackHelper.SetAttribute("PacketSize", UintegerValue(42));

    //         // アプリケーションをインストール
    //         ApplicationContainer apps = attackHelper.Install(attacker);

    //         NS_ABORT_MSG_IF(apps.GetN() != 1, "Expected exactly one application");

    //         Ptr<OnOffRetargetApplication> app = DynamicCast<OnOffRetargetApplication>(apps.Get(0));

    //         NS_ABORT_MSG_IF(!app, "OnOffRetargetApplication cast failed");

    //         // 後からSetRemote()を呼ぶため保持
    //         attackerApps.push_back(app);

    //         apps.Start(Seconds(attackStart));

    //         apps.Stop(Seconds(experiment.simulationDuration));
    //     }

    //     carpetScheduler.applications.push_back(std::move(attackerApps));
    // }


    // // ===== 最初の宛先集合を記録 =====

    // Simulator::Schedule(
    //     Seconds(attackStart),
    //     &RecordCarpetTargets,
    //     &carpetScheduler,
    //     initialTargets);


    // // ===== 5秒後から宛先切り替え =====

    // if (attackStart + targetSwitchPeriod < experiment.simulationDuration)
    // {
    //     Simulator::Schedule(
    //         Seconds(attackStart + targetSwitchPeriod),
    //         &SwitchCarpetTargets,
    //         &carpetScheduler);
    // }

    // std::cout
    //     << "Carpet-bombing applications installed: "
    //     << attackerNodes.size() * simultaneousTargets
    //     << std::endl;

    // pcap設定
    // pcapを取得する場所（AS番号, Device ID）
    std::vector<std::pair<uint32_t, uint32_t>> capturePoints = {
        {174, asinterfaces.at(174).at(1311).interfaceId},
        {9299, asinterfaces.at(9299).at(8220).interfaceId},
        {55836, asinterfaces.at(55836).at(9583).interfaceId},
        {137409, asinterfaces.at(137409).at(28761).interfaceId},
        
        
        
        /* carpet-bombing用に新たに設定しなおす必要がある
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
        */
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

    Simulator::Stop(Seconds(experiment.simulationDuration));

    std::cout << "Starting simulation..." << std::endl;


    auto start = std::chrono::steady_clock::now();

    Simulator::Run();

    auto end = std::chrono::steady_clock::now();

    double elapsed =
        std::chrono::duration<double>(end - start).count();

    std::cout << "[PERF] Simulator::Run(): "
            << elapsed << " seconds" << std::endl;

    Simulator::Destroy();

    return 0;
}
