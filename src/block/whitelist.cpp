#include "block/whitelist.h"

#include <arpa/inet.h>
#include <sys/socket.h>

#include "block/whitelist.local.h"
#include "util/logger.h"

namespace RS::block {
bool whitelist::add(const std::string& ip) {
    uint32_t ip_net;
    if(inet_pton(AF_INET, ip.c_str(), &ip_net) != 1) {
        util::error("whitelist > add > bad ip: ", ip);
        return false;
    }
    ips_.insert(ip_net);
    return true;
}
bool whitelist::add(const std::string& ip, const std::string& mask) {
    uint32_t ip_net;
    uint32_t mask_net;
    if(inet_pton(AF_INET, ip.c_str(), &ip_net) != 1) {
        util::error("whitelist > add > bad ip: ", ip);
        return false;
    }
    if(inet_pton(AF_INET, mask.c_str(), &mask_net) != 1) {
        util::error("whitelist > add > bad mask: ", mask);
        return false;
    }
    nets_.push_back({ip_net & mask_net, mask_net});	// 호스트 비트를 지워서 저장
    return true;
}
bool whitelist::contains(uint32_t ip) const {
    if(ips_.contains(ip)) return true;
    for(const auto& [net, mask] : nets_) {
        if((ip & mask) == net) return true;
    }
    return false;
}

bool load_local_whitelist(whitelist& wl) {
    bool ok = true;
    for(const auto& e : WHITELIST_ENTRIES) {
        if(e.mask == nullptr) {
            if(wl.add(e.ip)) util::info("[whitelist] local ", e.ip, " (", e.note, ")");
            else ok = false;
        } else {
            if(wl.add(e.ip, e.mask)) util::info("[whitelist] local ", e.ip, "/", e.mask, " (", e.note, ")");
            else ok = false;
        }
    }
    return ok;
}
}
