
#ifndef VARIABLE_PACKET_UDP_APPLICATION_H
#define VARIABLE_PACKET_UDP_APPLICATION_H

#include "ns3/application.h"
#include "ns3/address.h"
#include "ns3/data-rate.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/random-variable-stream.h"
#include "ns3/socket.h"

#include <cstdint>

namespace ns3
{

class VariablePacketUdpApplication : public Application
{
  public:
    static TypeId GetTypeId();

    VariablePacketUdpApplication();

    void Setup(Address peer,
               double rateBps,
               uint32_t minPacketSize,
               uint32_t maxPacketSize);

    int64_t AssignStream(int64_t stream);

  private:
    void StartApplication() override;
    void StopApplication() override;

    void SendPacket();
    void ScheduleNextPacket(uint32_t packetSize);

    Ptr<Socket> m_socket;
    Address m_peer;
    EventId m_sendEvent;

    double m_rateBps = 0;
    uint32_t m_minPacketSize = 64;
    uint32_t m_maxPacketSize = 1472;

    Ptr<UniformRandomVariable> m_packetSizeRv;
    bool m_running = false;
};

} // namespace ns3

#endif
