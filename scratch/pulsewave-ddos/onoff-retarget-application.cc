//
// Copyright (c) 2006 Georgia Tech Research Corporation
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation;
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
// Author: George F. Riley<riley@ece.gatech.edu>
//

// ns3 - On/Off Data Source Application class
// George F. Riley, Georgia Tech, Spring 2007
// Adapted from ApplicationOnOff in GTNetS.

/* Note by Pascal Kiechl<pascal.kiechl@uzh.ch>:
 * This file is an adaptation of the OnOff-Application by the above author (George F. Riley) that is
 * part of ns-3. It includes modifications that allow for a number of additional functionalities:
 *      - Setting a new remote to be able to dynamically switch the target to which traffic is sent
 *          This includes closing and opening a new socket, such that it works with protocols with
 *          handshake/teardown procedures such as TCP.
 *          This cycling of sockets also relies on a patch that (presumably) will be part of ns-3
 *          as of Version 3.39. See PATCHES.md for context.
 *      - A number of attack vector specific interactions regarding the use of specific protocols
 *          with the RawSocketImplementation, as well as taking into account attack vector (or
 *          protocol) properties when computing data rate, packet size and packet creation.
 *          Credit for the TCP SYN and ICMP attack vector implementations go to Calvin Falter, as
 *          they have been taken from his EDDD project with only very minor changes
 *      - Ability to set flags to force immediate send upon start and/or changing the remote to cut
 *          through any potential delays that stem from the cycling of on/off states
 *      - Ability to configure data rate fluctuations based on a simple normal distribution
 */

#include "onoff-retarget-application.h"

#include "ns3/address.h"
#include "ns3/boolean.h"
#include "ns3/data-rate.h"
#include "ns3/icmpv4.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/log.h"
// #include "ns3/mpi-interface.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/packet-socket-address.h"
#include "ns3/packet.h"
#include "ns3/pointer.h"
#include "ns3/random-variable-stream.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/socket.h"
#include "ns3/string.h"
#include "ns3/tcp-socket-base.h"
#include "ns3/tcp-socket.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-header.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/uinteger.h"

#include <random>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("OnOffRetargetApplication");

NS_OBJECT_ENSURE_REGISTERED(OnOffRetargetApplication);

TypeId
OnOffRetargetApplication::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::OnOffRetargetApplication")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<OnOffRetargetApplication>()
            .AddAttribute("DataRate",
                          "The data rate in on state.",
                          DataRateValue(DataRate("500kb/s")),
                          MakeDataRateAccessor(&OnOffRetargetApplication::m_cbrRate),
                          MakeDataRateChecker())
            .AddAttribute("PacketSize",
                          "The size of packets sent in on state",
                          UintegerValue(512),
                          MakeUintegerAccessor(&OnOffRetargetApplication::m_pktSize),
                          MakeUintegerChecker<uint32_t>(1))
            .AddAttribute("Remote",
                          "The address of the destination",
                          AddressValue(),
                          MakeAddressAccessor(&OnOffRetargetApplication::m_peer),
                          MakeAddressChecker())
            .AddAttribute("Local",
                          "The Address on which to bind the socket. If not set, it is generated "
                          "automatically.",
                          AddressValue(),
                          MakeAddressAccessor(&OnOffRetargetApplication::m_local),
                          MakeAddressChecker())
            .AddAttribute("OnTime",
                          "A RandomVariableStream used to pick the duration of the 'On' state.",
                          StringValue("ns3::ConstantRandomVariable[Constant=1.0]"),
                          MakePointerAccessor(&OnOffRetargetApplication::m_onTime),
                          MakePointerChecker<RandomVariableStream>())
            .AddAttribute("OffTime",
                          "A RandomVariableStream used to pick the duration of the 'Off' state.",
                          StringValue("ns3::ConstantRandomVariable[Constant=1.0]"),
                          MakePointerAccessor(&OnOffRetargetApplication::m_offTime),
                          MakePointerChecker<RandomVariableStream>())
            .AddAttribute("MaxBytes",
                          "The total number of bytes to send. Once these bytes are sent, "
                          "no packet is sent again, even in on state. The value zero means "
                          "that there is no limit.",
                          UintegerValue(0),
                          MakeUintegerAccessor(&OnOffRetargetApplication::m_maxBytes),
                          MakeUintegerChecker<uint64_t>())
            .AddAttribute("Protocol",
                          "The type of protocol to use. This should be "
                          "a subclass of ns3::SocketFactory",
                          TypeIdValue(UdpSocketFactory::GetTypeId()),
                          MakeTypeIdAccessor(&OnOffRetargetApplication::m_tid),
                          // This should check for SocketFactory as a parent
                          MakeTypeIdChecker())
            .AddAttribute("EnableSeqTsSizeHeader",
                          "Enable use of SeqTsSizeHeader for sequence number and timestamp",
                          BooleanValue(false),
                          MakeBooleanAccessor(&OnOffRetargetApplication::m_enableSeqTsSizeHeader),
                          MakeBooleanChecker())
            .AddAttribute("SkipFirstOffTime",
                          "Enable to skip the initial offTime, therefore start sending "
                          "immediately on application start.",
                          BooleanValue(false),
                          MakeBooleanAccessor(&OnOffRetargetApplication::m_skipFirstOffTime),
                          MakeBooleanChecker())
            .AddAttribute("RawProtocol",
                          "The integer which identifies the protocol to be used when using the a "
                          "raw socket type such as Ipv4RawSocketImpl",
                          IntegerValue(-1),
                          MakeIntegerAccessor(&OnOffRetargetApplication::m_protocol),
                          MakeIntegerChecker<int64_t>())
            .AddAttribute(
                "SourcePort",
                "The integer which determines the source port when using a transport layer "
                "attack vector. -1 means random, other values set the source port to a fixed port",
                IntegerValue(-1),
                MakeIntegerAccessor(&OnOffRetargetApplication::m_srcPort),
                MakeIntegerChecker<int64_t>())
            .AddAttribute(
                "DestinationPort",
                "The integer which determines the destination port when using a transport layer "
                "attack vector. -1 means random, other values set the destination port to a fixed "
                "port",
                IntegerValue(-1),
                MakeIntegerAccessor(&OnOffRetargetApplication::m_destPort),
                MakeIntegerChecker<int64_t>())
            .AddAttribute("AttackVector",
                          "The enum (integer) representing the attack vector. Only really needed "
                          "when using RawProtocol to determine exact behaviour, in case there are "
                          "multiple vectors that use the same underlying RawProtocol",
                          IntegerValue(-1),
                          MakeIntegerAccessor(&OnOffRetargetApplication::m_attackVector),
                          MakeIntegerChecker<int64_t>())
            .AddAttribute(
                "MaxDataRateFluctuation",
                "Determines the maximum data rate variation per individual packet.",
                DoubleValue(0.0),
                MakeDoubleAccessor(&OnOffRetargetApplication::m_maxDataRateDeviationPercent),
                MakeDoubleChecker<double>())
            .AddAttribute(
                "SkipFirstScheduleAfterRemoteChange",
                "Enable to immediately start sending after a remote change.",
                BooleanValue(false),
                MakeBooleanAccessor(&OnOffRetargetApplication::m_skipOffTimeAfterRemoteChange),
                MakeBooleanChecker())
            .AddTraceSource("Tx",
                            "A new packet is created and is sent",
                            MakeTraceSourceAccessor(&OnOffRetargetApplication::m_txTrace),
                            "ns3::Packet::TracedCallback")
            .AddTraceSource(
                "TxWithAddresses",
                "A new packet is created and is sent",
                MakeTraceSourceAccessor(&OnOffRetargetApplication::m_txTraceWithAddresses),
                "ns3::Packet::TwoAddressTracedCallback")
            .AddTraceSource(
                "TxWithSeqTsSize",
                "A new packet is created with SeqTsSizeHeader",
                MakeTraceSourceAccessor(&OnOffRetargetApplication::m_txTraceWithSeqTsSize),
                "ns3::PacketSink::SeqTsSizeCallback");
    return tid;
}

OnOffRetargetApplication::OnOffRetargetApplication()
    : m_socket(nullptr),
      m_connected(false),
      m_residualBits(0),
      m_lastStartTime(Seconds(0)),
      m_totBytes(0),
      m_unsentPacket(nullptr)
{
    NS_LOG_FUNCTION(this);
    PopulatePacketSizeOffsetMap();

    // https://stackoverflow.com/a/13445752
    std::random_device dev;
    std::mt19937 gen(dev());
    std::uniform_real_distribution<> initialSeedRange(0, 1000000); // arbitrary range
    // set initial value of seed used for port randomization. Drawn directly from random device on
    // each application individually to ensure that not all attacker nodes randomize their port
    // based on the same seed, thus in the same order
    m_seedIncrement = initialSeedRange(gen);
}

OnOffRetargetApplication::~OnOffRetargetApplication()
{
    NS_LOG_FUNCTION(this);
}

void
OnOffRetargetApplication::SetMaxBytes(uint64_t maxBytes)
{
    NS_LOG_FUNCTION(this << maxBytes);
    m_maxBytes = maxBytes;
}

Ptr<Socket>
OnOffRetargetApplication::GetSocket() const
{
    NS_LOG_FUNCTION(this);
    return m_socket;
}

int64_t
OnOffRetargetApplication::AssignStreams(int64_t stream)
{
    NS_LOG_FUNCTION(this << stream);
    m_onTime->SetStream(stream);
    m_offTime->SetStream(stream + 1);
    return 2;
}

void
OnOffRetargetApplication::DoDispose()
{
    NS_LOG_FUNCTION(this);

    CancelEvents();
    m_socket = nullptr;
    m_unsentPacket = nullptr;
    // chain up
    Application::DoDispose();
}

// Application Methods
void
OnOffRetargetApplication::StartApplication() // Called at time specified by Start
{
    NS_LOG_FUNCTION(this);

    // Create the socket if not already
    if (!m_socket)
    {
        ManageSocketCreation();
    }
    m_cbrRateFailSafe = m_cbrRate;
}

void
OnOffRetargetApplication::StopApplication() // Called at time specified by Stop
{
    NS_LOG_FUNCTION(this);

    CancelEvents();
    if (m_socket)
    {
        m_socket->Close();
    }
    else
    {
        NS_LOG_WARN("OnOffApplication found null socket to close in StopApplication");
    }
}

void
OnOffRetargetApplication::CancelEvents()
{
    NS_LOG_FUNCTION(this);

    m_cbrRateFailSafe = m_cbrRate;
    Simulator::Cancel(m_sendEvent);
    Simulator::Cancel(m_startStopEvent);
    // Canceling events may cause discontinuity in sequence number if the
    // SeqTsSizeHeader is header, and m_unsentPacket is true

    if (m_unsentPacket)
    {
        NS_LOG_DEBUG("Discarding cached packet upon CancelEvents ()");
    }
    m_unsentPacket = nullptr;
}

// Event handlers
void
OnOffRetargetApplication::StartSending()
{
    NS_LOG_FUNCTION(this);
    m_lastStartTime = Simulator::Now();
    ScheduleNextTx(); // Schedule the send packet event
    ScheduleStopEvent();
}

void
OnOffRetargetApplication::StopSending()
{
    NS_LOG_FUNCTION(this);
    CancelEvents();

    ScheduleStartEvent();
}

void
OnOffRetargetApplication::ManageSocketCreation()
{
    m_socket = Socket::CreateSocket(GetNode(), m_tid);
    if (m_protocol != -1)
    {
        // case where an attack vector uses a raw socket
        m_socket->SetAttribute("Protocol", UintegerValue(m_protocol));
    }
    int ret = -1;

    if (!m_local.IsInvalid())
    {
        NS_ABORT_MSG_IF((Inet6SocketAddress::IsMatchingType(m_peer) &&
                         InetSocketAddress::IsMatchingType(m_local)) ||
                            (InetSocketAddress::IsMatchingType(m_peer) &&
                             Inet6SocketAddress::IsMatchingType(m_local)),
                        "Incompatible peer and local address IP version");
        ret = m_socket->Bind(m_local);
    }
    else
    {
        if (Inet6SocketAddress::IsMatchingType(m_peer))
        {
            ret = m_socket->Bind6();
        }
        else if (InetSocketAddress::IsMatchingType(m_peer) ||
                 PacketSocketAddress::IsMatchingType(m_peer))
        {
            ret = m_socket->Bind();
        }
    }

    if (ret == -1)
    {
        NS_FATAL_ERROR("Failed to bind socket");
    }

    m_socket->SetConnectCallback(MakeCallback(&OnOffRetargetApplication::ConnectionSucceeded, this),
                                 MakeCallback(&OnOffRetargetApplication::ConnectionFailed, this));

    m_socket->Connect(m_peer);
    m_socket->SetAllowBroadcast(true);
    m_socket->ShutdownRecv();
}

void
OnOffRetargetApplication::ScheduleNextTx()
{
    NS_LOG_FUNCTION(this);

    if (m_maxBytes == 0 || m_totBytes < m_maxBytes)
    {
        NS_ABORT_MSG_IF(m_residualBits > m_pktSize * 8,
                        "Calculation to compute next send time will overflow");
        // for tcp syn, the packet size is ignored and empty packets are send. have to accordingly
        // correct for this in the data rate calculation here
        uint32_t pktSizeToUse = m_attackVector == AttackVector::tcp_syn_flooding
                                    ? m_pktSizeOffsets[tcp_syn_flooding]
                                    : m_pktSize;
        uint32_t bits = pktSizeToUse * 8 - m_residualBits;
        NS_LOG_LOGIC("bits = " << bits);
        // randomized delay based on a normal distribution to prevent "too perfect" traffic with
        // packets from within the same ASs arriving at the exact same time at the target.
        // Leads to more dynamic traffic patterns, although it must be noted that the choice of
        // distribution is not based on the statistical analysis of any real attack traffic data
        // and represents a pragmatic modelling choice
        double initial = bits / static_cast<double>(m_cbrRate.GetBitRate());
        double adjustment = 1 + GetRandomSendDelayModifier();
        double adjusted = adjustment * initial;
        Time nextTime = Seconds(adjusted);
        NS_LOG_LOGIC("nextTime = " << nextTime.As(Time::S));
        m_sendEvent = Simulator::Schedule(nextTime, &OnOffRetargetApplication::SendPacket, this);
    }
    else
    { // All done, cancel any pending events
        StopApplication();
    }
}

void
OnOffRetargetApplication::ScheduleStartEvent()
{ // Schedules the event to start sending data (switch to the "On" state)
    NS_LOG_FUNCTION(this);

    Time offInterval = Seconds(m_offTime->GetValue());
    NS_LOG_LOGIC("start at " << offInterval.As(Time::S));
    m_startStopEvent =
        Simulator::Schedule(offInterval, &OnOffRetargetApplication::StartSending, this);
}

void
OnOffRetargetApplication::ScheduleStopEvent()
{ // Schedules the event to stop sending data (switch to "Off" state)
    NS_LOG_FUNCTION(this);

    Time onInterval = Seconds(m_onTime->GetValue());
    NS_LOG_LOGIC("stop at " << onInterval.As(Time::S));
    m_startStopEvent =
        Simulator::Schedule(onInterval, &OnOffRetargetApplication::StopSending, this);
}

void
OnOffRetargetApplication::SendPacket()
{
    NS_LOG_FUNCTION(this);

    NS_ASSERT(m_sendEvent.IsExpired());

    Ptr<Packet> packet;
    if (m_unsentPacket)
    {
        packet = m_unsentPacket;
    }
    else if (m_attackVector == AttackVector::tcp_syn_flooding)
    {
        /*
         * TCP SYN requires special packet construction, mostly due to using the
         * Ipv4RawSocketImplementation
         *
         * NOTE! this implementation of syn flooding is taken from:
         * https://github.com/calvin-f/EDDD/tree/main by Calvin Falter, a similar project that was
         * running in parallel at our department.
         *
         * It is modified to allow for the explicit definition of specific ports or have them
         * randomized. Both for the destination port as well as the source port.
         */

        // create TCP header with syn flag
        TcpHeader header;
        header.SetFlags(TcpHeader::SYN);
        header.SetSourcePort(GetRandomPort());
        header.SetDestinationPort(GetRandomPort(true));

        // syn packets are created as empty packets, c.f., TcpSocketBase::SendEmptyPacket
        packet = Create<Packet>();
        packet->AddHeader(header);
    }
    else if (m_attackVector == AttackVector::icmp_flooding)
    {
        /*
         * ICMP Flooding requires special packet construction, also due to using the
         * Ipv4RawSocketImplementation
         *
         * NOTE! this implementation of icmp flooding is taken from:
         * https://github.com/calvin-f/EDDD/tree/main by Calvin Falter, a similar project that was
         * running in parallel at our department.
         *
         * I only modified it as far as that I adapted it to the control flow of this particular
         * application implementation and enabled checksum in the icmp packet header, as well as
         * configurability of the packet size (i.e. size of payload in header).
         */

        // data packet, for ICMP-Flooding. the configured packet-size is used in the payload which
        // is included in the header, adjusted for the packet-type specific size overhead through
        // e.g., headers
        Ptr<Packet> dataPacket =
            Create<Packet>(m_pktSize - m_pktSizeOffsets[AttackVector::icmp_flooding]);
        Icmpv4Echo echo;
        echo.SetData(dataPacket);

        // new empty packet
        packet = Create<Packet>();
        packet->AddHeader(echo);

        Icmpv4Header header;
        // type 8 (ping) with code 0 (no codes),
        // c.f. https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
        header.SetType(Icmpv4Header::ICMPV4_ECHO);
        header.SetCode(0);
        // enable checksum, else you will get 'Checksum: 0x000 incorrect, should be
        // {some_actual_checksum}' when you open up the corresponding part in the pcap output
        header.EnableChecksum();

        packet->AddHeader(header);
    }
    else if (m_attackVector == AttackVector::udp_flooding)
    {
        packet = Create<Packet>(m_pktSize - m_pktSizeOffsets[AttackVector::udp_flooding]);
        // create UDP header with correct source and destination port
        UdpHeader udpHeader;
        udpHeader.SetSourcePort(GetRandomPort());
        udpHeader.SetDestinationPort(GetRandomPort(true));
        packet->AddHeader(udpHeader);
    }

    m_socket->Send(packet);

    m_residualBits = 0;
    m_lastStartTime = Simulator::Now();
    ScheduleNextTx();
}

double
OnOffRetargetApplication::GetRandomSendDelayModifier() const
{
    std::random_device dev;
    std::mt19937 gen(dev());
    // set range to twice the max, given that it is in either direction
    std::uniform_real_distribution<> distribution(0, 2 * m_maxDataRateDeviationPercent);
    // subtract half the range such that both negative and positive values are possible
    double delayModifierPercent = distribution(gen) - m_maxDataRateDeviationPercent;
    return delayModifierPercent;
}

int
OnOffRetargetApplication::GetRandomPort(bool isDestPort)
{
    // courtesy of https://github.com/calvin-f/EDDD/tree/main by Calvin Falter, as part of his
    // syn flooding implementation which is adopted here. slightly modified to account for explicitly
    // configured port numbers

    if (isDestPort)
    {
        if (m_destPort != -1)
        {
            return m_destPort;
        }
    }
    else
    {
        if (m_srcPort != -1)
        {
            return m_srcPort;
        }
    }

    std::mt19937 gen(m_seedIncrement++);
    std::uniform_int_distribution<uint16_t> dis(0, 65535);
    uint32_t randomPort = dis(gen);
    return randomPort;
}

void
OnOffRetargetApplication::ConnectionSucceeded(Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << socket);

    if (m_skipFirstOffTime || m_skipOffTimeAfterRemoteChange)
    {
        m_skipFirstOffTime = false; // flag only impactful on first connection
        StartSending();
    }
    else
    {
        ScheduleStartEvent();
    }
    m_connected = true;
}

void
OnOffRetargetApplication::ConnectionFailed(Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << socket);
    NS_FATAL_ERROR("Can't connect");
}

void
OnOffRetargetApplication::PopulatePacketSizeOffsetMap()
{
    // The reason these offsets are needed, is to ensure that the correct 'size on wire' is achieved
    // i.e., that the 'size on wire' observed in the pcap output equals the configured m_pktSize,
    // because that m_pktSize is used for the calculation that determines the interval between
    // packets, thus ultimately implementing the data rate.

    // values calculated based on the effective packet size observed in the resulting pcap files
    // this value is to subtracted from the configured m_pktSize when creating the packets
    m_pktSizeOffsets[AttackVector::icmp_flooding] = 30;
    m_pktSizeOffsets[AttackVector::udp_flooding] = 30;
    // for tcp syn the offset means something different. TCP SYN packets are empty packets therefore
    // in the context of tcp syn within the control flow of this application, the
    // offset here is to be understood as the actual packet-size and not as a difference of sort,
    // because that difference would very with the configured packet size (since it is never
    // actually applied to the packets)
    // 42 -> 20 from syn packet, 20 from ip header, 2 from point-to-point protocol
    m_pktSizeOffsets[AttackVector::tcp_syn_flooding] = 42;

    // values based on the difference between effective packet size observed in resulting pcap files
    // and the returned buffer byte size of m_socket->Send(packet) (or of packet->GetSize(), which
    // returns the same value.
    // this value is to be subtracted from the configured m_pktSize when doing the comparison to
    // the returned buffer byte size value
    m_pktSizeOffsetsToBuffer[AttackVector::icmp_flooding] = 22;
    m_pktSizeOffsetsToBuffer[AttackVector::udp_flooding] = 30;
}

int
OnOffRetargetApplication::GetRemotePort()
{
    InetSocketAddress asISA = InetSocketAddress::ConvertFrom(m_peer);
    return asISA.GetPort();
}

void
OnOffRetargetApplication::SetRemote(InetSocketAddress address)
{
    NS_LOG_FUNCTION(this << address);
    // Given that TCP is supported, have to ensure connection is closed before switching remote
    // close old socket, set new peer
    m_socket->Close();
    m_connected = false;
    m_peer = address;

    // Ensure no pending event
    CancelEvents();

    // create new socket with new peer ( identical logic as in StartApplication() )
    ManageSocketCreation();
    m_cbrRateFailSafe = m_cbrRate;
}

} // Namespace ns3