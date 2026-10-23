#ifndef PARSER_H
#define PARSER_H

#include <netinet/ip.h>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "packet/frame_RS.h"
#include "packet/ip_RS.h"

namespace RS::scnet {

/**
 * frame : Ethernet 헤더부터 시작하는 프레임, len : 프레임 길이
 * 반환은 frame_RS. type()으로 ip_RS / arp_RS를 가른다. IPv4, ARP 외의 프레임은 -4.
 * rescode 정상:객체,code=0, 에러:nullptr,code<0, 제외(스킵):nullptr,code>0
 */
std::unique_ptr<packet::frame_RS> parse_frame(const uint8_t* frame, size_t len, int& rescode);
/**
 * 검증된 IP 헤더와 L4 시작 위치로 프로토콜에 맞는 ip_RS 하위 객체를 만든다. parse_frame()이 부른다.
 * l4avail: 버퍼에 남은 길이, tot_len: IP 헤더의 total length. L4 헤더 길이 검사에 둘 다 쓴다.
 * 모르는 프로토콜이면 nullptr, rescode 0 (오류 아님). 할당 실패는 -11.
 */
std::unique_ptr<packet::ip_RS> get_ip_RS(const iphdr* ip, const uint8_t* l4,
    const size_t l4avail, const size_t ip_header_len, const size_t tot_len, int& rescode);

}

#endif
