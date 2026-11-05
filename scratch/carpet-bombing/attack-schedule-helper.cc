#include "attack-schedule-helper.h"

#include <stdexcept>

AttackScheduleHelper::AttackScheduleHelper(const AttackConfig& config, int numTargets): m_attackConfig(config), m_numTargets(numTargets)
{
    if (numTargets <= 0 ||
        config.attackVectors.empty() ||
        config.burstDuration <= 0.0 ||
        config.targetSwitchDuration < 0.0)
    {
        throw std::invalid_argument("Invalid attack schedule configuration");
    }

    BuildSchedule();
}

void AttackScheduleHelper::BuildSchedule()
{
    CalculateOnOffTimes();
    CalculateApplicationStartTimes();
    CalculateRemoteSwitchIntervals();
}

void AttackScheduleHelper::CalculateApplicationStartTimes()
{
    double previousVectorDuration = 0.0;

    for (const auto& vector : m_attackConfig.attackVectors)
    {
        (void)vector;

        m_startTimes.push_back(previousVectorDuration);

        previousVectorDuration +=
            (m_attackConfig.burstDuration +
             m_attackConfig.targetSwitchDuration) * m_numTargets;
    }
}

void AttackScheduleHelper::CalculateOnOffTimes()
{
    double burst = m_attackConfig.burstDuration;
    double switchDuration = m_attackConfig.targetSwitchDuration;

    m_totalCycleDuration =
        m_attackConfig.attackVectors.size() *
        m_numTargets *
        (burst + switchDuration);

    for (const auto& vector : m_attackConfig.attackVectors)
    {
        (void)vector;

        double onTime = burst;

        double offTime =
            m_totalCycleDuration -
            (m_numTargets * burst) -
            ((m_numTargets - 1) * switchDuration);

        m_onOffTimes.push_back({onTime, offTime});
    }
}

void AttackScheduleHelper::CalculateRemoteSwitchIntervals()
{
    double burst = m_attackConfig.burstDuration;
    double switchDuration = m_attackConfig.targetSwitchDuration;

    for (size_t i = 0; i < m_attackConfig.attackVectors.size(); ++i)
    {
        double standardCase = burst + switchDuration;

        auto [onTime, offTime] = m_onOffTimes[i];

        double lastTargetCase = burst + offTime;

        m_remoteSwitchTimes.push_back({
            standardCase,
            lastTargetCase
        });
    }
}

double AttackScheduleHelper::GetNextRemoteChangeInterval(
    int vectorIndex,
    int targetIndex) const
{
    auto [standardCase, lastTargetCase] =
        m_remoteSwitchTimes.at(vectorIndex);

    if (targetIndex + 1 == m_numTargets)
    {
        return lastTargetCase;
    }

    return standardCase;
}

std::pair<double, double>
AttackScheduleHelper::GetOnOffTime(int index) const
{
    return m_onOffTimes.at(index);
}

double AttackScheduleHelper::GetStartTime(int index) const
{
    return m_startTimes.at(index);
}

int AttackScheduleHelper::GetNextTargetIndex(int index) const
{
    return (index + 1) % m_numTargets;
}

double AttackScheduleHelper::GetTotalCycleDuration() const
{
    return m_totalCycleDuration;
}