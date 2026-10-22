#include "scnet/ip_UDP_RS.h"

#include <netinet/in.h>

namespace RS::scnet {

ip_UDP_RS::ip_UDP_RS(const iphdr *ip, const udphdr *udp) : ip_RS(ip, ip_RS_type::UDP) {
    sport_ = ntohs(udp->uh_sport);
    dport_ = ntohs(udp->uh_dport);
}
void ip_UDP_RS::print(std::ostream &os) const {
    os << "UDP " << src() << ":" << sport_ << " -> " << dst() << ":" << dport_;
}

}