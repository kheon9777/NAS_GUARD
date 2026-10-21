#ifndef IP_TCP_RS_H
#define IP_TCP_RS_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstdint>
#include <ostream>

#include "scnet/ip_RS.h"

namespace RS::scnet {

class ip_TCP_RS : public ip_RS {
private:
    bool flag_syn_; // S
    bool flag_fin_; // F
    bool flag_rst_; // R
    bool flag_ack_; // .
    uint16_t sport_;
    uint16_t dport_;
public:
    ip_TCP_RS(const iphdr* ip, const tcphdr* tcp);
    ~ip_TCP_RS();
    bool is_flag_S() const;
    void print(std::ostream& os) const override;
};

}

#endif