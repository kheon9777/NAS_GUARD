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
#include <cstdio>
#include <string>
#include <unordered_map>

// =======================================
/* filter u_TCP u_UDP u_ICMP */

// #define u_TCP
// #define u_UDP
#define u_ICMP
// =======================================

namespace RS::scnet {
int ready_rawsock() {
    // 1. 모든 패킷을 받는 raw 소켓 열기
    // AF_PACKET : 네트워크 층 가장 아래, 랜카드 바로 위에서 패킷을 받겠다.
    // SOCK_RAW : Ethernet 헤더를 포함한 프레임 다 받는다. 
    // 세 번째 인자 : 패킷 거르는 필터링, ETH_P_ALL은 다 받는다는 소리
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    return fd;
}

int rawsock_do(int fd) {
    // std::unordered_map<uint32_t, ICMP_history> icmp_list;
    uint8_t buffer[65536];
    // ChroTimer timer{"tm"};

    const char* proto_str = nullptr;
    char src[INET_ADDRSTRLEN] = {};
    char dst[INET_ADDRSTRLEN] = {};
    std::optional<uint16_t> sport;
    std::optional<uint16_t> dport;
    std::string flag = "";
    size_t payload_len = 0;

    sockaddr_ll form;
    socklen_t form_len = sizeof(form);

    // 2. 패킷 하나 받기
    // fd : 시스템 콜로 요청해서 커널에게 부여받은, I/O자원 접근에 필요한 정수 
    // 커널은 모든 프로세스에 대한 각각의 fd관리 테이블을 저장하고 있음. 시스템콜이 오면 그 프로세스의 fd테이블에서 찾아 어떤 자원인지 식별해서 작업을 수행함
    ssize_t len = recvfrom(fd, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&form), &form_len);
    if (len < 0) {
        perror("recv");
        return -2;
    }

    if(form.sll_pkttype == PACKET_OUTGOING) {
        return -2;
    }

    if (len < static_cast<ssize_t>(sizeof(ethhdr) + sizeof(iphdr))) {
        return -2;
    }

    // 4. Ethernet 헤더 해석, IPv4만 통과
    const ethhdr* eth = reinterpret_cast<const ethhdr*>(buffer);
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return -2;
    }

    // 5. Ethernet 헤더 바로 뒤가 IP 헤더
    const iphdr* ip = reinterpret_cast<const iphdr*>(buffer + sizeof(ethhdr));
    size_t frame_len = static_cast<size_t>(len);
    size_t ip_header_len = static_cast<size_t>(ip->ihl) * 4;
    
    // 패킷 유효성 검사
    // ihl : IP헤더길이. 4바이트 배수로 표현하게 만들었음(iph필드가 4비트밖에 안되서 0~15밖에 표현 못함)
    if(ip->ihl < 5 || frame_len < sizeof(ethhdr) + ip_header_len) {
        return -2;
    }
    size_t tot_len = ntohs(ip->tot_len);
    if(tot_len < ip_header_len || tot_len > frame_len - sizeof(ethhdr)) {
        return -2;
    }
    size_t l4offset = sizeof(ethhdr) + ip_header_len;
    const uint8_t* l4 = buffer + l4offset;
    size_t l4avail = frame_len - l4offset;

    switch (ip->protocol)
    {
    case IPPROTO_TCP: {
#ifndef u_TCP
return -2;
#endif
        if(l4avail < sizeof(tcphdr)) {
            return -2;
        }
        proto_str = "TCP";
        flag += "[";
        const tcphdr* tcp = reinterpret_cast<const tcphdr*>(l4);
        size_t tcp_header_len = static_cast<size_t>(tcp->doff) * 4;
        if(tcp_header_len < sizeof(tcphdr) || l4avail < tcp_header_len) {
            return -2;
        }
        if(tot_len < ip_header_len + tcp_header_len) {
            return -2;
        }
        if(tcp->syn) flag += "S";
        if(tcp->fin) flag += "F";
        if(tcp->rst) flag += "R";
        if(tcp->ack) flag += ".";
        flag += "] ";
        sport = ntohs(tcp->th_sport);
        dport = ntohs(tcp->th_dport);
        payload_len = tot_len - ip_header_len - tcp_header_len;
        break;
    }
    
    case IPPROTO_UDP: {
#ifndef u_UDP
return -2;
#endif
        if(l4avail < sizeof(udphdr)) {
            return -2;
        }
        if(tot_len < ip_header_len + sizeof(udphdr)) {
            return -2;
        }
        proto_str = "UDP";
        const udphdr* udp = reinterpret_cast<const udphdr*>(l4);
        sport = ntohs(udp->uh_sport);
        dport = ntohs(udp->uh_dport);
        payload_len = tot_len - ip_header_len - sizeof(udphdr);
        break;
    }
    case IPPROTO_ICMP: {
#ifndef u_ICMP
return -2;
#endif
        if(l4avail < sizeof(icmphdr)) {
            return -2;
        }
        if(tot_len < ip_header_len + sizeof(icmphdr)) {
            return -2;
        }
        proto_str = "ICMP";
        const icmphdr* icmp = reinterpret_cast<const icmphdr*>(l4);
        if(icmp->type == ICMP_ECHO) {
            flag = "echo request ";
        } else if (icmp->type == ICMP_ECHOREPLY) {
            flag = "echo reply ";
        } else {
            flag = "type " + std::to_string(icmp->type) + " ";
        }
        payload_len = tot_len - ip_header_len - sizeof(icmphdr);
        break;
    }
    default:
        return -2;
        break;
    }

    // SSH 연결은 무시
    if(sport == 22 || dport == 22) 
        return -2;

    // 6. IP 주소를 문자열로 변환
    inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));

    // 7. 출력 (protocol: 1=ICMP, 6=TCP, 17=UDP)
    if(sport.has_value() && dport.has_value()) {
        printf("%s %s:%u -> %s:%u %s%zu bytes\n",
            proto_str,
            src,
            static_cast<unsigned int>(*sport),
            dst,
            static_cast<unsigned int>(*dport),
            flag.c_str(),
            payload_len
        );
    } else {
        printf("%s %s -> %s %s%zu bytes\n",
            proto_str,
            src,
            dst,
            flag.c_str(),
            payload_len
        );
    }
    return 0;
}
}