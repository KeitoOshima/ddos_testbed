#ifndef ATTACK_VECTOR_H
#define ATTACK_VECTOR_H

namespace ns3
{

enum AttackVector
{
    udp_flooding,
    icmp_flooding,
    tcp_syn_flooding
};

} // namespace ns3

#endif