#ifndef EXPERIMENT_CONFIG_READER_H
#define EXPERIMENT_CONFIG_READER_H

#include "experiment-config.h"

#include <string>

class ExperimentConfigReader
{
public:
    static ExperimentConfig Load(const std::string& filePath);
};

#endif