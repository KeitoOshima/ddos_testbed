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

struct InterfacesInfo{
    uint32_t interfaceId;
    Ipv4Address address;
    Ipv4Mask mask;
};

// 初期設定のアドレスとマスク
ns3::Ipv4Address baseAddress("10.0.0.0");
ns3::Ipv4Mask netMask("255.255.255.252");

std::string targetdir = "./ASrouteInfo";


std::map<uint32_t, std::vector<NeighborInfo>> ReadTopologyFromFile(const std::string& filename) {
    std::map<uint32_t, std::vector<NeighborInfo>> topology;
    std::ifstream topology_file(filename);
    if (!topology_file.is_open()) {
        std::cerr << "Failed to open topology file: " << filename << std::endl;
        return topology;
    }

    std::string line;
    while (std::getline(topology_file, line)) {
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
            topology[asn].push_back({neighbor_asn, relationship});
        }
    }
    return topology;
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
        std::cout << "aspart = [" << aspart.substr(2) << "]" << std::endl;
        uint32_t asn = std::stoul(aspart.substr(2));

        // 1. ASノードの存在チェック
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
            std::cout << "src_asn = " << asn << "dst_asn = " << dst_asn << "nexthop_part = [" << nexthop_part << "]" << std::endl;
            uint32_t nexthop_asn = std::stoul(nexthop_part);

                asn = 12779;
    nexthop_asn = 29513;
    std::cout << "src=" << asn
          << " nexthop=" << nexthop_asn
          << std::endl;

std::cout << "asinterfaces contains src: "
          << asinterfaces.contains(asn)
          << std::endl;

std::cout << "src contains nexthop: "
          << (asinterfaces.contains(asn)
              && asinterfaces.at(asn).contains(nexthop_asn))
          << std::endl;

            node->AddNetworkRouteTo(ipv4, mask, asinterfaces.at(nexthop_asn).at(asn).address, asinterfaces.at(asn).at(nexthop_asn).interfaceId);


        }

    }
}

int main (int argc, char *argv[])
{
  // uint32_t nNodes = 4996;
  double simTime = 10.0;

  GlobalValue::Bind(
    "SimulatorImplementationType",
    StringValue("ns3::RealtimeSimulatorImpl"));

    GlobalValue::Bind(
    "ChecksumEnabled",
    BooleanValue(true));


  auto topology = ReadTopologyFromFile("as_topology.txt");
  std::map<uint32_t, Ptr<Node>> asNodes;

  for (const auto& [asn, neighbors] : topology) {
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
  ns3::Ipv4AddressHelper ipv4;



  uint32_t link_num = 0;
  uint32_t as_num = 0;
  for (const auto& [asn, neighbors] : topology) {

      for (const auto& neighbor : neighbors) {
            uint32_t neighbor_asn = neighbor.asn;
    
            uint32_t large_asn = std::max(asn, neighbor_asn);
            uint32_t small_asn = std::min(asn, neighbor_asn);

            std::pair<uint32_t, uint32_t> link_pair = {small_asn, large_asn};

            if (createdLinks.find(link_pair) != createdLinks.end()) {
                continue;
            }
            
            Ptr<Node> node1 = asNodes[asn];
            Ptr<Node> node2 = asNodes[neighbor_asn];

            NodeContainer link(node1, node2);
            NetDeviceContainer devices = p2p.Install(link);

            createdLinks.insert({small_asn, large_asn});
            link_num++;
            std::cout << "Number of links: " << link_num << std::endl;

            ipv4.SetBase(baseAddress, netMask);
            // assignメソッドを使わず、自分で実装 (assignはIPの重複確認の処理が入っているが、時間がかかるので不採用)
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

            Ipv4Address address1(baseAddress.Get() + 1);
            Ipv4Address address2(baseAddress.Get() + 2);

            ipv4Node1->AddAddress(if1, Ipv4InterfaceAddress(address1, netMask));
            ipv4Node2->AddAddress(if2, Ipv4InterfaceAddress(address2, netMask));

            ipv4Node1->SetMetric(if1, 1);
            ipv4Node2->SetMetric(if2, 1);

            ipv4Node1->SetUp(if1);
            ipv4Node2->SetUp(if2);

            asinterfaces[asn][neighbor_asn] = {if1, address1, netMask};
            asinterfaces[neighbor_asn][asn] = {if2, address2, netMask};

            baseAddress = ns3::Ipv4Address(baseAddress.Get() + 4);
        }


        as_num++;
        std::cout << "Number of AS nodes: " << as_num << std::endl;
    }






    routingTableGenerator(targetdir, asNodes, asinterfaces);

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
