#include "experiment-config-reader.h"

#include <yaml-cpp/yaml.h>

#include <stdexcept>
#include <string>

ExperimentConfig
ExperimentConfigReader::Load(const std::string& filePath)
{
    YAML::Node root = YAML::LoadFile(filePath);

    ExperimentConfig config;

    // 1. グローバル設定
    YAML::Node global = root["global_settings"];

    config.pcapPrefix =
        global["capture"]["pcap_prefix"].as<std::string>();

    config.simulationDuration =
        global["scheduling"]["simulation_duration_s"].as<double>();

    // 2. 攻撃設定
    YAML::Node attack = global["attack"];

    config.attack.burstDuration =
        attack["burst_duration_s"].as<double>();

    config.attack.targetSwitchDuration =
        attack["target_switch_duration_s"].as<double>();

    // 3. 攻撃ベクトル
    for (const auto& vector : attack["attack_vectors"])
    {
        AttackVectorConfig v;

        v.type = vector["type"].as<std::string>();
        v.dataRate = vector["data_rate"].as<std::string>();

        if (vector["packet_size"])
        {
            v.packetSize = vector["packet_size"].as<uint32_t>();
        }

        config.attack.attackVectors.push_back(v);
    }

    // 4. 攻撃者
    for (const auto& attacker : root["attacker_nodes"])
    {
        NodeConfig node;

        node.networkAddress =
            attacker["network_address"].as<std::string>();

        node.asNumber =
            attacker["as_number"].as<std::string>();

        config.attackers.push_back(node);
    }

    // 5. 被害者
    for (const auto& target : root["target_server_nodes"])
    {
        NodeConfig node;

        node.networkAddress =
            target["network_address"].as<std::string>();

        node.asNumber =
            target["as_number"].as<std::string>();

        config.targets.push_back(node);
    }

    return config;
}