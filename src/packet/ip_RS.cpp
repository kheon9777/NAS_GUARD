#include "packet/ip_RS.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace RS::packet {
void ip_RS::print(std::ostream& os) const {
    os << src_str() << " -> " << dst_str();
}
ip_RS::ip_RS(const iphdr* ip, ip_RS_type proto)
: frame_RS(frame_type::ip), src_(ip->saddr), dst_(ip->daddr), proto_(proto), payload_len_(0), is_fault_(0) {
}
const uint32_t& ip_RS::src() const {
    return src_;
}
const uint32_t& ip_RS::dst() const {
    return dst_;
}
std::string ip_RS::src_str() const {
    char buff[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src(), buff, sizeof(buff));
    return buff;
}
std::string ip_RS::dst_str() const {
    char buff[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dst(), buff, sizeof(buff));
    return buff;
}
ip_RS_type ip_RS::proto() const {
    return proto_;
}
bool ip_RS::is_proto(ip_RS_type val) const {
    return proto_ == val;
}
uint8_t ip_RS::is_fault() const {
    return is_fault_;
}
size_t ip_RS::payload_len() const {
    return payload_len_;
}
void ip_RS::set_payload_len(size_t val) {
    payload_len_ = val;
}
}
