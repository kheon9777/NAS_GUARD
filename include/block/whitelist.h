#ifndef WHITELIST_H
#define WHITELIST_H

#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace RS::block {

/**
 * 감지, 차단에서 제외할 IP 목록. 단일 IP와 대역(네트워크 주소 + 마스크)을 모두 받는다.
 * 모든 값은 네트워크 바이트 순서로 보관한다.
 * add()는 던지지 않고 bool로 알린다 (SIGHUP 리로드는 루프 경로라 예외를 쓰지 않음).
 */
class whitelist {
private:
    std::unordered_set<uint32_t> ips_;
    std::vector<std::pair<uint32_t, uint32_t>> nets_;	// (network, mask)
public:
    bool add(const std::string& ip);	// 단일 IP ("1.2.3.4"). 형식이 틀리면 로그 남기고 false
    bool add(const std::string& ip, const std::string& mask);	// 대역 (ip & mask를 network로 저장)
    bool contains(uint32_t ip) const;	// 단일 IP 집합 조회 후 대역 순회. 루프 경로에서 패킷마다 호출
    size_t size() const { return ips_.size() + nets_.size(); }	// 항목 수 (로그용)
};

/**
 * whitelist.local.h의 상수 표(개인 IP, 커밋 안 됨)를 wl에 더한다. DB 항목은 store::load_whitelist()가 이 위에 더한다.
 * 항목이 잘못되면 로그 남기고 false (나머지 항목은 계속 넣는다).
 */
bool load_local_whitelist(whitelist& wl);

}

#endif
