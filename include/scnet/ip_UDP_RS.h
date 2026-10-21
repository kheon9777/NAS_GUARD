#ifndef IP_UDP_RS_H
#define IP_UDP_RS_H

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <cstdint>
#include <ostream>

#include "scnet/ip_RS.h"

namespace RS::scnet {

class ip_UDP_RS : public ip_RS {
private:
    uint16_t sport_;
    uint16_t dport_;
public:
    ip_UDP_RS(const iphdr* ip, const udphdr* udp);
    void print(std::ostream& os) const override;
};
}

#endif