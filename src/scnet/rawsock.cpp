#include "scnet/rawsock.h"

#include <arpa/inet.h>  
#include <linux/if_ether.h>  
#include <linux/if_packet.h>   
#include <netinet/in.h> 
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>  
#include <unistd.h>   

#include <cerrno>
#include <cstdint>
#include <cstring>      
#include <iostream>
#include <memory>
#include <system_error>

#include "scnet/ip_ICMP_RS.h"
#include "scnet/ip_TCP_RS.h"
#include "scnet/ip_UDP_RS.h"
#include "util/logger.h"

#define EXCEPT_SELF

namespace RS::scnet {

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
        throw std::system_error(errno, std::generic_category(), "ready_rawsock > socket");
    }
    return fd;
}

void close_rawsock(int fd) {
    close(fd);
}

/**
 * rescode 정상:ip_RS,code=0, 에러:nullptr,code<0, 제외(스킵):nullptr,code>0
 */
std::unique_ptr<ip_RS> rawsock_recv(int fd, int& rescode) {
    uint8_t buffer[65536];
    sockaddr_ll form;
    socklen_t form_len = sizeof(form);
    rescode = 0;

    ssize_t len = recvfrom(fd, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&form), &form_len);
    if (len < 0) {
        util::logger("rawsock_recv > recvfrom");
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
        return 1;
    } 
#endif
    std::cout << *target << "\n";
    return 0;
}

}