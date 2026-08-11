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

using namespace ns3;

struct NeighborInfo {
    uint32_t asn;
    std::string relationship;
};

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

            createdLinks.insert({asn, neighbor_asn});
            link_num++;
        }
        as_num++;
    }

    std::cout << "Number of AS nodes: " << as_num << std::endl;
    std::cout << "Number of links: " << link_num << std::endl;

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
