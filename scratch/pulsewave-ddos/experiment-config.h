#ifndef EXPERIMENT_CONFIG_H
#define EXPERIMENT_CONFIG_H

#include <cstdint>
#include <string>
#include <vector>

struct AttackVectorConfig
{
    std::string type;
    uint32_t packetSize = 0;
    std::string dataRate;
};

struct AttackConfig
{
    double burstDuration = 0.0;
    double targetSwitchDuration = 0.0;
    std::vector<AttackVectorConfig> attackVectors;
};

struct NodeConfig
{
    std::string networkAddress;
    std::string asNumber;
};

struct ExperimentConfig
{
    std::string pcapPrefix;
    double simulationDuration = 0.0;

    AttackConfig attack;

    std::vector<NodeConfig> attackers;
    std::vector<NodeConfig> targets;
};

#endif