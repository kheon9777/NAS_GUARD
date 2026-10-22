#ifndef IP_TCP_RS_H
#define IP_TCP_RS_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstdint>
#include <ostream>

#include "packet/ip_RS.h"

namespace RS::packet {

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
    bool is_flag_no_ACK() const;
    void print(std::ostream& os) const override;
    uint16_t sport() const;
    uint16_t dport() const;
};

}

#endif
