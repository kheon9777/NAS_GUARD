#ifndef PARSER_H
#define PARSER_H

#include <netinet/ip.h>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "packet/ip_RS.h"

namespace RS::scnet {

/**
 * frame : Ethernet 헤더부터 시작하는 프레임, len : 프레임 길이
 * rescode 정상:ip_RS,code=0, 에러:nullptr,code<0, 제외(스킵):nullptr,code>0
 */
std::unique_ptr<packet::ip_RS> parse_frame(const uint8_t* frame, size_t len, int& rescode);
std::unique_ptr<packet::ip_RS> get_ip_RS(const iphdr* ip, const uint8_t* l4,
    const size_t l4avail, const size_t ip_header_len, const size_t tot_len, int& rescode);

}

#endif
