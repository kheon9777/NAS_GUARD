#include "packet/ip_UDP_RS.h"

#include <netinet/in.h>

namespace RS::packet {

ip_UDP_RS::ip_UDP_RS(const iphdr* ip, const udphdr* udp) : ip_RS(ip, ip_RS_type::UDP) {
    sport_ = ntohs(udp->uh_sport);
    dport_ = ntohs(udp->uh_dport);
}
void ip_UDP_RS::print(std::ostream& os) const {
    os << "UDP " << src_str() << ":" << sport_ << " -> " << dst_str() << ":" << dport_;
}

uint16_t ip_UDP_RS::sport() const {
    return sport_;
}
uint16_t ip_UDP_RS::dport() const {
    return dport_;
}
}
