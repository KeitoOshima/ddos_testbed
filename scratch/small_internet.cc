#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
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
    uint32_t offset = 4;
};

std::string targetdir = "./ASrouteInfo";


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
            state.offset = 4;
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
        state.offset = 4;


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


int main (int argc, char *argv[])
{
    double simTime = 900.0;

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

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute ("DataRate", StringValue ("10Mbps"));
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

    routingTableGenerator(targetdir, asNodes, asinterfaces);

    SetupTapConnections(tapnode, asNodes, asPrefixes);

    std::cout << "finish setting routing tables" << std::endl;

    // pcap出力
    // p2p.EnablePcapAll("as-topology");

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
