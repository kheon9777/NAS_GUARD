#include "scnet/ip_RS.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/tcp.h>      
#include <netinet/udp.h>      
#include <netinet/ip_icmp.h>  
#include <netinet/in.h>
#include <iostream>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <memory>

#include "util/logger.h"
#include "scnet/ip_RS.h"

namespace RS::scnet {
void ip_RS::print(std::ostream &os) const {
    os << src_ << " -> " << dst_;
}
ip_RS::ip_RS(const iphdr* ip, ip_RS_type proto)
: proto_(proto), payload_len_(0), is_fault_(0) {
    inet_ntop(AF_INET, &ip->saddr, src_, sizeof(src_));
    inet_ntop(AF_INET, &ip->daddr, dst_, sizeof(dst_));
}
const char *ip_RS::src() const {
    return src_;
}
const char *ip_RS::dst() const {
    return dst_;
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
std::ostream& operator << (std::ostream& os, const ip_RS& ip) {
    ip.print(os);
    return os;
}
}