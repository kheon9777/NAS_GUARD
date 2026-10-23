#ifndef IP_TCP_RS_H
#define IP_TCP_RS_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstdint>
#include <ostream>

#include "packet/ip_RS.h"

namespace RS::packet {

// TCP 패킷. 플래그와 포트. 포트는 호스트 순서
class ip_TCP_RS : public ip_RS {
private:
    bool flag_syn_;	// S
    bool flag_fin_;	// F
    bool flag_rst_;	// R
    bool flag_ack_;	// .
    uint16_t sport_;
    uint16_t dport_;
public:
    ip_TCP_RS(const iphdr* ip, const tcphdr* tcp);	// 길이 검증은 파서가 끝낸 뒤
    bool is_flag_S() const;	// SYN
    bool is_flag_no_ACK() const;	// ACK 없음. SYN과 스텔스 스캔(FIN, NULL 등)을 함께 잡는 기준. 맺어진 연결의 패킷은 전부 ACK가 있음
    void print(std::ostream& os) const override;	// "src:sport -> dst:dport [SFR.]"
    uint16_t sport() const;	// 호스트 순서 (ntohs 끝남)
    uint16_t dport() const;
};

}

#endif
