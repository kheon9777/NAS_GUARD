#ifndef IP_RS_H
#define IP_RS_H

#include <netinet/ip.h>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>

#include "packet/frame_RS.h"

namespace RS::packet {
// L4 프로토콜. proto()로 하위 클래스를 가른다
enum class ip_RS_type {
    TCP, UDP, ICMP
};

/**
 * IPv4 패킷의 공통 부분 (출발지, 목적지, L4 종류). 하위 클래스가 L4 헤더를 든다.
 * IP는 네트워크 바이트 순서 uint32_t로 들고 있고, 문자열은 필요할 때 inet_ntop으로 만든다 (루프 경로에서 할당을 피하려고).
 */
class ip_RS : public frame_RS {
private:
    uint32_t src_;
    uint32_t dst_;
    ip_RS_type proto_;
protected:
    size_t payload_len_;
    uint8_t is_fault_;	// 해석 중 이상이 있었는지 (지금은 항상 0)
    void print(std::ostream& os) const override;	// "src -> dst". 하위 클래스가 포트 등을 덧붙임
public:
    ip_RS(const iphdr* ip, const ip_RS_type proto);	// 검증된 IP 헤더에서 주소를 복사
    const uint32_t& src() const;	// 네트워크 순서. 참조라 inet_ntop에 바로 넘길 수 있음
    const uint32_t& dst() const;
    std::string src_str() const;	// "1.2.3.4". 할당하므로 루프 경로에서는 피할 것
    std::string dst_str() const;
    ip_RS_type proto() const;
    bool is_proto(ip_RS_type val) const;
    uint8_t is_fault() const;
    size_t payload_len() const;	// L4 헤더 뒤 데이터 길이. 파서가 set_payload_len()으로 채움
    void set_payload_len(size_t val);
};

}

#endif
