#include "packet/ip_TCP_RS.h"

#include <netinet/in.h>

namespace RS::packet {
ip_TCP_RS::ip_TCP_RS(const iphdr* ip, const tcphdr* tcp)
: ip_RS(ip, ip_RS_type::TCP), flag_syn_(false), flag_fin_(false), flag_rst_(false), flag_ack_(false) {
    sport_ = ntohs(tcp->th_sport);
    dport_ = ntohs(tcp->th_dport);
    if(tcp->syn) flag_syn_ = true;
    if(tcp->fin) flag_fin_ = true;
    if(tcp->rst) flag_rst_ = true;
    if(tcp->ack) flag_ack_ = true;
}
bool ip_TCP_RS::is_flag_S() const {
    return flag_syn_ && !flag_ack_;
}
bool ip_TCP_RS::is_flag_no_ACK() const {
    return !flag_ack_;
}
void ip_TCP_RS::print(std::ostream& os) const {
    os << "TCP " << src_str() << ":" << sport_ << " -> " << dst_str() << ":" << dport_ << " [";
    if(flag_syn_) os << "S";
    if(flag_fin_) os << "F";
    if(flag_rst_) os << "R";
    if(flag_ack_) os << ".";
    os << "]";
}
uint16_t ip_TCP_RS::sport() const {
    return sport_;
}
uint16_t ip_TCP_RS::dport() const {
    return dport_;
}
}
