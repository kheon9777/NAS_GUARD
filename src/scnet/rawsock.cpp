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
    virtual void print(std::ostream& os) const {
        os << src_ << " -> " << dst_;
    }
public:
    ip_RS(const iphdr* ip, const ip_RS_type proto) : is_fault_(false), payload_len_(0), proto_(proto) {
        inet_ntop(AF_INET, &ip->saddr, src_, sizeof(src_));
        inet_ntop(AF_INET, &ip->daddr, dst_, sizeof(dst_));  
    }
    virtual ~ip_RS() = default;
    const char* src() const {
        return src_;
    }
    const char* dst() const {
        return dst_;
    }
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

class ip_UDP_RS : public ip_RS {
private:
    uint16_t sport_;
    uint16_t dport_;
public:
    ip_UDP_RS(const iphdr* ip, const udphdr* udp) : ip_RS(ip, ip_RS_type::UDP) {
        sport_ = ntohs(udp->uh_sport);
        dport_ = ntohs(udp->uh_dport);
        payload_len_ = 8;
        // payload_len = tot_len - ip_header_len - sizeof(udphdr);
    }
    void print(std::ostream& os) const override {
        os << "UDP " << src() << ":" << sport_ << " -> " << dst() << ":" << dport_;
    }
};

class ip_ICMP_RS : public ip_RS {
private:
    bool type_echo_;    // echo request
    bool type_echorp_;  // echo replay
    uint8_t type_;      // other type
public:
    ip_ICMP_RS(const iphdr* ip, const icmphdr* icmp) 
    : ip_RS(ip, ip_RS_type::ICMP), type_echo_(false), type_echorp_(false), type_(0) {
        if(icmp->type == ICMP_ECHO) {
            type_echo_ = true;
        } else if (icmp->type == ICMP_ECHOREPLY) {
            type_echorp_ = true;
        }
        type_ = icmp->type;

        payload_len_ = 9;
        // payload_len = tot_len - ip_header_len - sizeof(udphdr);
    }    
    void print(std::ostream& os) const override {
        os << "ICMP " << src() << " -> " << dst();
        if(type_echo_) os << " echo";
        else if(type_echorp_) os << " echo reply";
        else os << " type=" << type_;
    }
};

std::unique_ptr<ip_RS> get_ip_RS(const iphdr* ip, const uint8_t* l4, const size_t l4avail,
const size_t ip_header_len, const size_t tot_len, int& rescode) {
    std::unique_ptr<ip_RS>res(nullptr);
    rescode = 0;
    switch (ip->protocol) {
    case IPPROTO_TCP: {
        if(l4avail < sizeof(tcphdr)) {  // 길이 문제
            rescode = -8;
            break;
        }
        const tcphdr* tcp = reinterpret_cast<const tcphdr*>(l4);
        size_t tcp_header_len = static_cast<size_t>(tcp->doff) * 4;
        if(tcp_header_len < sizeof(tcphdr) || l4avail < tcp_header_len) {
            rescode = -9;
            break;
        }
        if(tot_len < ip_header_len + tcp_header_len) {
            rescode = -10;
            break;
        }
        uint16_t sport = ntohs(tcp->th_sport);
        uint16_t dport = ntohs(tcp->th_dport);
        if(sport == 22 || dport == 22) {    // 22포트 스킵
            rescode = 1;
            break;
        }
        res.reset(new ip_TCP_RS{ip, tcp});
        res->set_payload_len(tot_len - ip_header_len - tcp_header_len);
        break;
    }
    case IPPROTO_UDP: {
        if(l4avail < sizeof(udphdr)) {
            rescode = -8;
            break;
        }
        if(tot_len < ip_header_len + sizeof(udphdr)) {
            rescode = -10;
            break;
        }
        const udphdr* udp = reinterpret_cast<const udphdr*>(l4);
        res.reset(new ip_UDP_RS{ip, udp});
        res->set_payload_len(tot_len - ip_header_len - sizeof(udphdr));
        break;
    }
    case IPPROTO_ICMP: {
        if(l4avail < sizeof(icmphdr)) {
            rescode = -8;
            break;
        }
        if(tot_len < ip_header_len + sizeof(icmphdr)) {
            rescode = -10;
            break;
        }
        const icmphdr* icmp = reinterpret_cast<const icmphdr*>(l4);
        res.reset(new ip_ICMP_RS{ip, icmp});
        res->set_payload_len(tot_len - ip_header_len - sizeof(icmphdr));
        break;
    }
    }

    return res;
}

int ready_rawsock() {
    // 1. 모든 패킷을 받는 raw 소켓 열기
    // AF_PACKET : 네트워크 층 가장 아래, 랜카드 바로 위에서 패킷을 받겠다.
    // SOCK_RAW : Ethernet 헤더를 포함한 프레임 다 받는다. 
    // 세 번째 인자 : 패킷 거르는 필터링, ETH_P_ALL은 다 받는다는 소리
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        throw std::system_error(errno, std::generic_category(), "ready_rawsocket > socket");
    }
    return fd;
}

void close_rawsock(int fd) {
    close(fd);
}

/**
 * return 정상:ip_RS,code=0, 에러:nullptr,code<0, 제외(스킵):nullptr,code>0
 */
std::unique_ptr<ip_RS> rawsock_recv(int fd, int& rescode) {
    uint8_t buffer[65536];
    sockaddr_ll form;
    socklen_t form_len = sizeof(form);
    rescode = 0;

    ssize_t len = recvfrom(fd, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&form), &form_len);
    if (len < 0) {
        util::logger("rawsock_do > recvfrom");
        rescode = -2;
        return nullptr;
    }

    /**
     * 아웃바운드 패킷 스킵
     */
    if(form.sll_pkttype == PACKET_OUTGOING) {
        rescode = 1;
        return nullptr;
    }

    if (len < static_cast<ssize_t>(sizeof(ethhdr) + sizeof(iphdr))) {
        rescode = -3;
        return nullptr;
    }

    // 4. Ethernet 헤더 해석, IPv4만 통과
    const ethhdr* eth = reinterpret_cast<const ethhdr*>(buffer);
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        rescode = -4;
        return nullptr;
    }

    // 5. Ethernet 헤더 바로 뒤가 IP 헤더
    const iphdr* ip = reinterpret_cast<const iphdr*>(buffer + sizeof(ethhdr));
    size_t frame_len = static_cast<size_t>(len);
    size_t ip_header_len = static_cast<size_t>(ip->ihl) * 4;
    
    // 패킷 유효성 검사
    // ihl : IP헤더길이. 4바이트 배수로 표현하게 만들었음(iph필드가 4비트밖에 안되서 0~15밖에 표현 못함)
    if(ip->ihl < 5 || frame_len < sizeof(ethhdr) + ip_header_len) {
        rescode = -5;
        return nullptr;
    }
    size_t tot_len = ntohs(ip->tot_len);
    if(tot_len < ip_header_len || tot_len > frame_len - sizeof(ethhdr)) {
        rescode = -6;
        return nullptr;
    }
    size_t l4offset = sizeof(ethhdr) + ip_header_len;
    const uint8_t* l4 = buffer + l4offset;
    size_t l4avail = frame_len - l4offset;

    int get_ip_resultcode = 0;
    std::unique_ptr<ip_RS> target = get_ip_RS(ip, l4, l4avail, ip_header_len, tot_len, get_ip_resultcode);
    if(target == nullptr) rescode = -7;
    if(get_ip_resultcode != 0) rescode = get_ip_resultcode;

    return target;
}

int rawsock_do(int fd) {
    int rescode = 0;
    // return :
    // (정상)ip_RS,code=0, (에러)nullptr,code<0, (제외, 스킵):nullptr,code>0
    std::unique_ptr<ip_RS> target = rawsock_recv(fd, rescode);
    if(rescode != 0) return rescode;

#ifdef EXCEPT_SELF
    if((std::strncmp(target->src(), "127.0.0.1", sizeof("127.0.0.1")) == 0) && 
        (std::strncmp(target->dst(), "127.0.0.1", sizeof("127.0.0.1")) == 0)) {
        return -1;
    } 
#endif

    // 7. 출력 (protocol: 1=ICMP, 6=TCP, 17=UDP)
    std::cout << *target << "\n";
    return 0;
}


}