#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/tcp.h>      
#include <netinet/udp.h>      
#include <netinet/ip_icmp.h>  
#include <netinet/in.h>
#include <optional>
#include <linux/if_packet.h>
#include <iostream>

#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <unistd.h>
#include <memory>

#include "scnet/rawsock.h"
#include "util/logger.h"

class ip_TCP_RS : public ip_RS {
private:
    bool flag_syn_; // S
    bool flag_fin_; // F
    bool flag_rst_; // R
    bool flag_ack_; // .
    uint16_t sport_;
    uint16_t dport_;
    /* data */
public:
    ip_TCP_RS(const iphdr* ip, const tcphdr* tcp) 
    : ip_RS(ip, ip_RS_type::TCP), flag_syn_(false), flag_fin_(false), flag_rst_(false), flag_ack_(false) {
        sport_ = ntohs(tcp->th_sport);
        dport_ = ntohs(tcp->th_dport);
        size_t tcp_header_len = static_cast<size_t>(tcp->doff) * 4;
        if(tcp->syn) flag_syn_ = true;
        if(tcp->fin) flag_fin_ = true;
        if(tcp->rst) flag_rst_ = true;
        if(tcp->ack) flag_ack_ = true;

        // payload_len = tot_len - ip_header_len - tcp_header_len;
        payload_len_ = 7;
    }
    ~ip_TCP_RS() {

    }

    bool is_flag_S() const {
        return flag_syn_ && !flag_ack_;
    }

    void print(std::ostream& os) const override {
        os << "TCP " << src() << ":" << sport_ << " -> " << dst() << ":" << dport_ << " [";
        if(flag_syn_) os << "S";
        if(flag_fin_) os << "F";
        if(flag_rst_) os << "R";
        if(flag_ack_) os << ".";
        os << "]";
    }
};