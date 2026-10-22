#include "scnet/ip_ICMP_RS.h"

namespace RS::scnet {

ip_ICMP_RS::ip_ICMP_RS(const iphdr *ip, const icmphdr *icmp) 
: ip_RS(ip, ip_RS_type::ICMP), type_echo_(false), type_echorp_(false), type_(0) {
    if(icmp->type == ICMP_ECHO) {
        type_echo_ = true;
    } else if (icmp->type == ICMP_ECHOREPLY) {
        type_echorp_ = true;
    }
    type_ = icmp->type;
}    

void ip_ICMP_RS::print(std::ostream &os) const {
    os << "ICMP " << src() << " -> " << dst();
    if(type_echo_) os << " echo";
    else if(type_echorp_) os << " echo reply";
    else os << " type=" << type_;
}

}