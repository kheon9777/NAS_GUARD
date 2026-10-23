#ifndef ARP_RS_H
#define ARP_RS_H

#include <netinet/if_ether.h>
#include <cstdint>
#include <ostream>

#include "packet/frame_RS.h"

namespace RS::packet {

/**
 * ARP 프레임. 장비 감지에 쓰는 건 sender(MAC, IP) 쌍이다.
 * sender MAC은 이더넷 헤더가 아니라 ARP 본문의 것을 쓴다 (상대 ARP 캐시에 들어가는 값이 이쪽).
 * IP는 네트워크 바이트 순서.
 */
class arp_RS : public frame_RS {
private:
    uint16_t opcode_;	// ARPOP_REQUEST 1, ARPOP_REPLY 2
    uint64_t sender_mac_;
    uint32_t sender_ip_;
    uint32_t target_ip_;
protected:
    void print(std::ostream& os) const override;	// "ARP request 10.0.0.2 (mac) -> 10.0.0.1"
public:
    explicit arp_RS(const ether_arp* arp);	// 검증된(이더넷 + IPv4) ARP 본문에서 필드를 복사
    bool is_request() const;	// opcode 1
    bool is_reply() const;	// opcode 2
    bool is_gratuitous() const;	// sender == target. 묻지도 않았는데 "내가 x다"라고 알리는 ARP
    uint64_t sender_mac() const;	// ARP 본문의 sender MAC (mac_pack 형식)
    uint32_t sender_ip() const;	// 네트워크 순서
    uint32_t target_ip() const;	// 네트워크 순서
};

}

#endif
