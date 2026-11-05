#ifndef ATTACK_SCHEDULE_HELPER_H
#define ATTACK_SCHEDULE_HELPER_H

#include "experiment-config.h"

#include <utility>
#include <vector>

class AttackScheduleHelper
{
public:
    AttackScheduleHelper(
        const AttackConfig& config,
        int numTargets
    );

    double GetNextRemoteChangeInterval(int vectorIndex, int targetIndex) const;

    std::pair<double, double> GetOnOffTime(int index) const;

    double GetStartTime(int index) const;

    int GetNextTargetIndex(int index) const;

    double GetTotalCycleDuration() const;

private:
    void BuildSchedule();

    void CalculateApplicationStartTimes();
    void CalculateOnOffTimes();
    void CalculateRemoteSwitchIntervals();

    AttackConfig m_attackConfig;

    int m_numTargets;
    double m_totalCycleDuration = 0.0;

    std::vector<std::pair<double, double>> m_onOffTimes;
    std::vector<double> m_startTimes;
    std::vector<std::pair<double, double>> m_remoteSwitchTimes;
};

#endif