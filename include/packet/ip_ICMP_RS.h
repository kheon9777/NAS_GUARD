#ifndef IP_ICMP_RS_H
#define IP_ICMP_RS_H

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <cstdint>
#include <ostream>

#include "packet/ip_RS.h"

namespace RS::packet {

// ICMP 패킷. 감지에 쓰는 건 echo request 여부만
class ip_ICMP_RS : public ip_RS {
private:
    bool type_echo_;	// echo request
    bool type_echorp_;	// echo replay
    uint8_t type_;	// other type
public:
    ip_ICMP_RS(const iphdr* ip, const icmphdr* icmp);	// 길이 검증은 파서가 끝낸 뒤
    bool is_echo_request() const;	// type 8. ICMP 플러드 감지는 이것만 센다
    void print(std::ostream& os) const override;
};

}

#endif
