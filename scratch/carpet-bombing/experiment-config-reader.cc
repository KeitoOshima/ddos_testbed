
#include "experiment-config-reader.h"

#include <yaml-cpp/yaml.h>

#include <stdexcept>
#include <string>

ExperimentConfig ExperimentConfigReader::Load(const std::string& filePath)
{
    YAML::Node root = YAML::LoadFile(filePath);

    ExperimentConfig config;

    // 1. グローバル設定
    YAML::Node global = root["global_settings"];

    config.pcapPrefix = global["capture"]["pcap_prefix"].as<std::string>();

    config.simulationDuration = global["scheduling"]["simulation_duration_s"].as<double>();

    // 2. Carpet-bombing設定
    YAML::Node carpet = global["attack"]["carpet_bombing"];

    if (!carpet)
    {
        throw std::runtime_error("Missing carpet_bombing configuration");
    }

    config.carpetBombing.targetPrefix = carpet["target_prefix"].as<std::string>();

    config.carpetBombing.candidateTargets = carpet["candidate_targets"].as<uint32_t>();

    config.carpetBombing.simultaneousTargets = carpet["simultaneous_targets"].as<uint32_t>();

    config.carpetBombing.targetOffset = carpet["target_offset"].as<uint32_t>();

    config.carpetBombing.totalRateBps = carpet["total_rate_bps"].as<uint64_t>();

    config.carpetBombing.attackStart = carpet["attack_start_s"].as<double>();

    config.carpetBombing.targetSwitchDuration = carpet["target_switch_duration_s"].as<double>();

    config.carpetBombing.targetSelection = carpet["target_selection"].as<std::string>();

    config.carpetBombing.trafficDistribution = carpet["traffic_distribution"].as<std::string>();

    // 3. 攻撃者ノード
    for (const auto& attacker : root["attacker_nodes"])
    {
        NodeConfig node;

        node.networkAddress = attacker["network_address"].as<std::string>();

        node.asNumber = attacker["as_number"].as<std::string>();

        config.attackers.push_back(node);
    }

    // 4. 被害者ノード
    for (const auto& target : root["target_server_nodes"])
    {
        NodeConfig node;

        node.networkAddress = target["network_address"].as<std::string>();

        node.asNumber = target["as_number"].as<std::string>();

        config.targets.push_back(node);
    }

    return config;
}
