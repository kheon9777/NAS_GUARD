#include "block/whitelist.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdexcept>

#include "packet/ip_TCP_RS.h"
#include "packet/ip_UDP_RS.h"

namespace RS::block {
void whitelist::add(const std::string& ip) {
    uint32_t ip_net;
    if(inet_pton(AF_INET, ip.c_str(), &ip_net) != 1) {
        throw std::invalid_argument("whitelist > add > bad ip: " + ip);
    }
    ips_.insert(ip_net);
}
void whitelist::add(const std::string& ip, const std::string& mask) {
    uint32_t ip_net;
    uint32_t mask_net;
    if(inet_pton(AF_INET, ip.c_str(), &ip_net) != 1) {
        throw std::invalid_argument("whitelist > add > bad ip: " + ip);
    }
    if(inet_pton(AF_INET, mask.c_str(), &mask_net) != 1) {
        throw std::invalid_argument("whitelist > add > bad mask: " + mask);
    }
    nets_.push_back({ip_net & mask_net, mask_net});     // 호스트 비트를 지워서 저장
}
bool whitelist::contains(uint32_t ip) const {
    if(ips_.contains(ip)) return true;
    for(const auto& [net, mask] : nets_) {
        if((ip & mask) == net) return true;
    }
    return false;
}
bool whitelist::contains_custom_filter(const packet::ip_RS& target) const {
    if(target.proto() == packet::ip_RS_type::TCP) {
        auto& tmp = static_cast<const packet::ip_TCP_RS&>(target);
        if(tmp.sport() == 22 || tmp.dport() == 22) {    // 22포트 스킵
            return true;
        }
    } else if(target.proto() == packet::ip_RS_type::UDP) {
        auto& tmp = static_cast<const packet::ip_UDP_RS&>(target);
        if(tmp.sport() == 22 || tmp.dport() == 22) {    // 22포트 스킵
            return true;
        }
    }
    return false;
}
}
