#ifndef IP_UDP_RS_H
#define IP_UDP_RS_H

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <cstdint>
#include <ostream>

#include "packet/ip_RS.h"

namespace RS::packet {

// UDP 패킷. 포트는 호스트 순서. 지금은 출력만 하고 감지에는 안 쓴다 (포트 스캔 감지기에서 쓸 예정)
class ip_UDP_RS : public ip_RS {
private:
    uint16_t sport_;
    uint16_t dport_;
public:
    ip_UDP_RS(const iphdr* ip, const udphdr* udp);	// 길이 검증은 파서가 끝낸 뒤
    void print(std::ostream& os) const override;
    uint16_t sport() const;	// 호스트 순서
    uint16_t dport() const;
};
}

#endif
