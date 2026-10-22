#ifndef IP_ICMP_RS_H
#define IP_ICMP_RS_H

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <cstdint>
#include <ostream>

#include "packet/ip_RS.h"

namespace RS::packet {

class ip_ICMP_RS : public ip_RS {
private:
    bool type_echo_;    // echo request
    bool type_echorp_;  // echo replay
    uint8_t type_;      // other type
public:
    ip_ICMP_RS(const iphdr* ip, const icmphdr* icmp);
    bool is_echo_request() const;
    void print(std::ostream& os) const override;
};

}

#endif
