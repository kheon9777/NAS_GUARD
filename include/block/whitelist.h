#ifndef WHITELIST_H
#define WHITELIST_H

#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "packet/ip_RS.h"

namespace RS::block {

/**
 * 감지, 차단에서 제외할 IP 목록. 단일 IP와 대역(네트워크 주소 + 마스크)을 모두 받는다.
 * 모든 값은 네트워크 바이트 순서로 보관한다.
 */
class whitelist {
private:
    std::unordered_set<uint32_t> ips_;
    std::vector<std::pair<uint32_t, uint32_t>> nets_;   // (network, mask)
public:
    void add(const std::string& ip);
    void add(const std::string& ip, const std::string& mask);
    bool contains(uint32_t ip) const;
    bool contains_custom_filter(const packet::ip_RS& target) const;   // 임시 정책: 22번 포트 제외
};

}

#endif
