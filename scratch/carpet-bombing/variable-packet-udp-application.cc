
#include "variable-packet-udp-application.h"

#include "ns3/abort.h"
#include "ns3/log.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/udp-socket-factory.h"

#include <algorithm>
#include <cmath>

namespace ns3
{

NS_OBJECT_ENSURE_REGISTERED(VariablePacketUdpApplication);

TypeId
VariablePacketUdpApplication::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::VariablePacketUdpApplication")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<VariablePacketUdpApplication>();

    return tid;
}

VariablePacketUdpApplication::VariablePacketUdpApplication()
{
    m_packetSizeRv = CreateObject<UniformRandomVariable>();
}

void
VariablePacketUdpApplication::Setup(
    Address peer,
    double rateBps,
    uint32_t minPacketSize,
    uint32_t maxPacketSize)
{
    NS_ABORT_MSG_IF(!std::isfinite(rateBps) || rateBps <= 0.0,
                "rateBps must be finite and positive");    NS_ABORT_MSG_IF(minPacketSize == 0, "minPacketSize must be positive");
    NS_ABORT_MSG_IF(minPacketSize > maxPacketSize,
                    "Invalid packet size range");

    m_peer = peer;
    m_rateBps = rateBps;
    m_minPacketSize = minPacketSize;
    m_maxPacketSize = maxPacketSize;
}

int64_t
VariablePacketUdpApplication::AssignStream(int64_t stream)
{
    m_packetSizeRv->SetStream(stream);
    return 1;
}

void
VariablePacketUdpApplication::StartApplication()
{
    m_running = true;

    m_socket = Socket::CreateSocket(
        GetNode(),
        UdpSocketFactory::GetTypeId());

    NS_ABORT_MSG_IF(!m_socket, "Failed to create UDP socket");

    // Explicitly bind the UDP socket.
    int bindResult = m_socket->Bind();

    NS_ABORT_MSG_IF(
        bindResult < 0,
        "UDP Bind failed"
        << " nodeId=" << GetNode()->GetId()
        << " socketError=" << static_cast<int>(m_socket->GetErrno())
        << " time=" << Simulator::Now().GetSeconds());

    int connectResult = m_socket->Connect(m_peer);

    NS_ABORT_MSG_IF(
        connectResult < 0,
        "UDP Connect failed"
        << " nodeId=" << GetNode()->GetId()
        << " socketError=" << static_cast<int>(m_socket->GetErrno())
        << " time=" << Simulator::Now().GetSeconds());

    SendPacket();
}

void
VariablePacketUdpApplication::StopApplication()
{
    m_running = false;

    if (m_sendEvent.IsPending())
    {
        Simulator::Cancel(m_sendEvent);
    }

    if (m_socket)
    {
        m_socket->Close();
        m_socket = nullptr;
    }
}

void
VariablePacketUdpApplication::SendPacket()
{
    if (!m_running)
    {
        return;
    }

    uint32_t packetSize =
        static_cast<uint32_t>(
            m_packetSizeRv->GetInteger(
                m_minPacketSize,
                m_maxPacketSize));

    Ptr<Packet> packet = Create<Packet>(packetSize);

    int sent = m_socket->Send(packet);

    if (sent < 0 ||
            static_cast<uint32_t>(sent) != packetSize)
        {
            NS_ABORT_MSG(
                "UDP send failed"
                << " nodeId=" << GetNode()->GetId()
                << " destination=" << InetSocketAddress::ConvertFrom(m_peer).GetIpv4()
                << " packetSize=" << packetSize
                << " sent=" << sent
                << " socketError=" << static_cast<int>(m_socket->GetErrno())
                << " time=" << Simulator::Now().GetSeconds());
        }

    ScheduleNextPacket(packetSize);
}

void
VariablePacketUdpApplication::ScheduleNextPacket(
    uint32_t packetSize)
{
    // Payload bit rate, consistent with OnOffApplication.
    long double intervalSeconds =
        (8.0L * packetSize) / m_rateBps;

    Time interval = Seconds(
        static_cast<double>(intervalSeconds));

    // Prevent a zero-time event loop at extreme rates.
    NS_ABORT_MSG_IF(interval.IsZero(),
                    "Packet interval below simulator time resolution");

    m_sendEvent = Simulator::Schedule(
        interval,
        &VariablePacketUdpApplication::SendPacket,
        this);
}

} // namespace ns3
