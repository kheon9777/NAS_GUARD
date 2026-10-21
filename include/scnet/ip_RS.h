#ifndef IP_RS_H
#define IP_RS_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <cstddef>
#include <cstdint>
#include <ostream>

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
    const char* src() const;
    const char* dst() const;
    ip_RS_type proto() const;
    bool is_proto(ip_RS_type val) const;
    uint8_t is_fault() const;
    size_t payload_len() const;
    void set_payload_len(size_t val);
    friend std::ostream& operator << (std::ostream& os, const ip_RS& ip);
};

}

#endif