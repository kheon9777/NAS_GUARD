#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/tcp.h>      
#include <netinet/udp.h>      
#include <netinet/ip_icmp.h>  
#include <netinet/in.h>
#include <iostream>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <memory>

#include "util/logger.h"
#include "scnet/ip_RS.h"

#define EXCEPT_SELF

namespace RS::scnet {

enum class ip_RS_type {
    TCP, UDP, ICMP
};

class ip_RS {
private:
    char src_[INET_ADDRSTRLEN];
    char dst_[INET_ADDRSTRLEN];
    ip_RS_type proto_;
protected:
    size_t payload_len_;
    uint8_t is_fault_;
    char mac_[12]; // TODO
    virtual void print(std::ostream& os) const;
public:
    ip_RS(const iphdr* ip, const ip_RS_type proto);
    virtual ~ip_RS() = default;
    const char* src();
    const char* dst();
    const ip_RS_type proto() const {
        return proto_;
    }
    bool is_proto(ip_RS_type val) const {
        return proto_ == val;
    }
    uint8_t is_fault() const {
        return is_fault_;
    }
    const size_t payload_len() const {
        return payload_len_;
    }
    void set_payload_len(size_t val) {
        payload_len_ = val;
    }
    friend std::ostream& operator << (std::ostream& os, const ip_RS& ip) {
        ip.print(os);
        return os;
    }
};
}