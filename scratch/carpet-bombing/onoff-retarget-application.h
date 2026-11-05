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

#ifndef ONOFF_RETARGET_APPLICATION_H
#define ONOFF_RETARGET_APPLICATION_H

#include "attack-vector.h"

#include "ns3/address.h"
#include "ns3/application.h"
#include "ns3/data-rate.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/seq-ts-size-header.h"
#include "ns3/tcp-socket.h"
#include "ns3/traced-callback.h"

#include <random>

namespace ns3
{

class Address;
class RandomVariableStream;
class Socket;

/**
 * \ingroup applications
 * \defgroup onoff OnOffApplication
 *
 * This traffic generator follows an On/Off pattern: after
 * Application::StartApplication
 * is called, "On" and "Off" states alternate. The duration of each of
 * these states is determined with the onTime and the offTime random
 * variables. During the "Off" state, no traffic is generated.
 * During the "On" state, cbr traffic is generated. This cbr traffic is
 * characterized by the specified "data rate" and "packet size".
 */
/**
 * \ingroup onoff
 *
 * \brief Generate traffic to a single destination according to an
 *        OnOff pattern.
 *
 * This traffic generator follows an On/Off pattern: after
 * Application::StartApplication
 * is called, "On" and "Off" states alternate. The duration of each of
 * these states is determined with the onTime and the offTime random
 * variables. During the "Off" state, no traffic is generated.
 * During the "On" state, cbr traffic is generated. This cbr traffic is
 * characterized by the specified "data rate" and "packet size".
 *
 * Note:  When an application is started, the first packet transmission
 * occurs _after_ a delay equal to (packet size/bit rate).  Note also,
 * when an application transitions into an off state in between packet
 * transmissions, the remaining time until when the next transmission
 * would have occurred is cached and is used when the application starts
 * up again.  Example:  packet size = 1000 bits, bit rate = 500 bits/sec.
 * If the application is started at time 3 seconds, the first packet
 * transmission will be scheduled for time 5 seconds (3 + 1000/500)
 * and subsequent transmissions at 2 second intervals.  If the above
 * application were instead stopped at time 4 seconds, and restarted at
 * time 5.5 seconds, then the first packet would be sent at time 6.5 seconds,
 * because when it was stopped at 4 seconds, there was only 1 second remaining
 * until the originally scheduled transmission, and this time remaining
 * information is cached and used to schedule the next transmission
 * upon restarting.
 *
 * If the underlying socket type supports broadcast, this application
 * will automatically enable the SetAllowBroadcast(true) socket option.
 *
 * If the attribute "EnableSeqTsSizeHeader" is enabled, the application will
 * use some bytes of the payload to store an header with a sequence number,
 * a timestamp, and the size of the packet sent. Support for extracting
 * statistics from this header have been added to \c ns3::PacketSink
 * (enable its "EnableSeqTsSizeHeader" attribute), or users may extract
 * the header via trace sources.  Note that the continuity of the sequence
 * number may be disrupted across On/Off cycles.
 */
class OnOffRetargetApplication : public Application
{
  public:
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();

    OnOffRetargetApplication();

    ~OnOffRetargetApplication() override;

    /**
     * \brief Set the total number of bytes to send.
     *
     * Once these bytes are sent, no packet is sent again, even in on state.
     * The value zero means that there is no limit.
     *
     * \param maxBytes the total number of bytes to send
     */
    void SetMaxBytes(uint64_t maxBytes);

    /**
     * \brief Return a pointer to associated socket.
     * \return pointer to associated socket
     */
    Ptr<Socket> GetSocket() const;

    /**
     * \brief Assign a fixed random variable stream number to the random variables
     * used by this model.
     *
     * \param stream first stream index to use
     * \return the number of stream indices assigned by this model
     */
    int64_t AssignStreams(int64_t stream);

    /**
     * \brief set the remote address
     * \param addr remote address
     * \param port remote port (in principle already included in addr)
     */
    void SetRemote(InetSocketAddress address);

    /**
     * \brief return the currently set remote port
     */
    int GetRemotePort();

    /**
     * \brief set application to skip the first On Time upon application start and start sending
     * directly \param value boolean value
     */
    void SkipFirstOnTime(bool value);

    /**
     * \brief set application to skip the first On Time upon remote change and start sending
     * directly \param value boolean value
     */
    void SkipOnTimeAfterRemoteChange(bool value);

  protected:
    void DoDispose() override;

  private:
    // inherited from Application base class.
    void StartApplication() override; // Called at time specified by Start
    void StopApplication() override;  // Called at time specified by Stop

    // helpers
    /**
     * \brief Cancel all pending events.
     */
    void CancelEvents();

    // Event handlers
    /**
     * \brief Start an On period
     */
    void StartSending();
    /**
     * \brief Start an Off period
     */
    void StopSending();
    /**
     * \brief Send a packet
     */
    void SendPacket();

    Ptr<Socket> m_socket;                //!< Associated socket
    Address m_peer;                      //!< Peer address
    Address m_local;                     //!< Local address to bind to
    bool m_connected;                    //!< True if connected
    Ptr<RandomVariableStream> m_onTime;  //!< rng for On Time
    Ptr<RandomVariableStream> m_offTime; //!< rng for Off Time
    DataRate m_cbrRate;                  //!< Rate that data is generated
    DataRate m_cbrRateFailSafe;          //!< Rate that data is generated (check copy)
    uint32_t m_pktSize;                  //!< Size of packets
    std::unordered_map<AttackVector, uint32_t>
        m_pktSizeOffsets; //!< Some packets have additional components (e.g., ICMP packet header)
                          //!< that contributes to overall packet-size. Basically this offset
                          //!< serves the purpose of ensuring that the resulting 'size on wire'
                          //!< in the pcap files matches the configured pktSize
    std::unordered_map<AttackVector, uint32_t>
        m_pktSizeOffsetsToBuffer; //!< Different size offset, this time between the observed 'size
                                  //!< on wire' and the packet buffer size returned when sending the
                                  //!< packet on the socket with m_socket->Send(packet)
    uint32_t m_residualBits;      //!< Number of generated, but not sent, bits
    Time m_lastStartTime;         //!< Time last packet sent
    uint64_t m_maxBytes;          //!< Limit total number of bytes sent
    uint64_t m_totBytes;          //!< Total bytes sent so far
    EventId m_startStopEvent;     //!< Event id for next start or stop event
    EventId m_sendEvent;          //!< Event id of pending "send packet" event
    TypeId m_tid;                 //!< Type of the socket used
    int m_seedIncrement{0};       //!< required for port randomization
    int m_protocol;               //!< Protocol to be used if using raw socket in m_tid
    int m_attackVector;           //!< Attack vector enum value. Needed if multiple attack vectors
                        //!< require specific behaviour with the same underlying RawProtocol
                        //!< (e.g., specially constructed packets)
    uint32_t m_seq{0};                   //!< Sequence
    Ptr<Packet> m_unsentPacket;          //!< Unsent packet cached for future attempt
    bool m_enableSeqTsSizeHeader{false}; //!< Enable or disable the use of SeqTsSizeHeader
    bool m_skipFirstOffTime{false}; //!< Enable to immediately start sending upon application start,
                                    //!< instead of after an initial OffTime value has passed
    bool m_skipOffTimeAfterRemoteChange{
        false}; //!< Enable to immediately start sending upon remote change, instead of after an
                //!< initial Offime value has passed

    /// Traced Callback: transmitted packets.
    TracedCallback<Ptr<const Packet>> m_txTrace;

    /// Callbacks for tracing the packet Tx events, includes source and destination addresses
    TracedCallback<Ptr<const Packet>, const Address&, const Address&> m_txTraceWithAddresses;

    /// Callback for tracing the packet Tx events, includes source, destination, the packet sent,
    /// and header
    TracedCallback<Ptr<const Packet>, const Address&, const Address&, const SeqTsSizeHeader&>
        m_txTraceWithSeqTsSize;

    // used to control the destination port on packets for appropriate attack vectors (TCP SYN, UDP)
    int m_destPort;
    // used to control the source port on packets for appropriate attack vectors (TCP SYN, UDP)
    int m_srcPort;
    // determines maximum data rate variation in either direction
    double m_maxDataRateDeviationPercent;

  private:
    /**
     * \brief Schedule the next packet transmission
     */
    void ScheduleNextTx();
    /**
     * \brief Schedule the next On period start
     */
    /**
     * \brief Calculate a modifier for the next packet schedule interval to achieve variation within
     *  the attack traffic data rate. Based on a simple uniform distribution for the purpose of
     * being pragmatic due to time constraints.
     */
    double GetRandomSendDelayModifier() const;
    /**
     * \brief Schedule the next On period start
     */
    void ScheduleStartEvent();
    /**
     * \brief Schedule the next Off period start
     */
    void ScheduleStopEvent();
    /**
     * \brief Handle a Connection Succeed event
     * \param socket the connected socket
     */
    void ConnectionSucceeded(Ptr<Socket> socket);
    /**
     * \brief Handle a Connection Failed event
     * \param socket the not connected socket
     */
    void ConnectionFailed(Ptr<Socket> socket);
    /**
     * \brief Create socket with set (or newly set through SetRemote) m_peer
     */
    void ManageSocketCreation();
    /**
     * \brief Fill in entries for protocol/attack-vector-specific size overhead in packets
     */
    void PopulatePacketSizeOffsetMap();
    /**
     * \brief Draw random port in range 0 - 65535 if no specific src/dest port is configured
     * (https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
     * \param isDestPort draw for destionation port instead of source port
     */
    int GetRandomPort(bool isDestPort = false);
};

} // namespace ns3

#endif /* ONOFF_RETARGET_APPLICATION_H */