// simple_dump.cpp
// 빌드: g++ -std=c++17 -Wall -Wextra -o simple_dump simple_dump.cpp
// 실행: sudo ./simple_dump

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <unistd.h>
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
#include <cstring>
#include <unordered_map>
#include <unordered_set>

#include "ChroTimer.h"

// =======================================
/* filter u_TCP u_UDP u_ICMP */

#define u_TCP
// #define u_UDP
// #define u_ICMP

#define EXCEPT_SELF
// =======================================

#define PORTCHECKDURATION_S 3   // N초동안 포트 요청 검사
#define KPORTTHRESHOLD 15       // 포트 탐색종류 N가지 이상인 경우 경고
#define DURATION 10             // IP 저장기간

struct ScanTracker {
    std::chrono::steady_clock::time_point watch_start;  // 감시시작시간
    std::chrono::steady_clock::time_point watch_last;   // 마지막확인시간
    std::unordered_set<uint16_t> ports;                 // 요청한포트보관
    int syn_cnt = 0;
    bool is_alert = false;
    char src[INET_ADDRSTRLEN];
};

std::ostream& operator<<(std::ostream& os, const ScanTracker& t) {
    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    std::chrono::duration<double> since_start = now - t.watch_start;
    std::chrono::duration<double> since_last = now - t.watch_last;

    os << "[" << t.src << "]" << " syn=" << t.syn_cnt << " ports=" << t.ports.size() << " {...";
    os << " }" << " alert=" << (t.is_alert ? "Y" : "N") << " start=" << since_start.count() << "s ago"
       << " last=" << since_last.count() << "s ago";
    return os;
}

double steady_diff (
    std::chrono::steady_clock::time_point from, 
    std::chrono::steady_clock::time_point to) 
{
    return std::chrono::duration<double>{to - from}.count();
}


int main() {
    std::unordered_map<uint32_t, ScanTracker> history;
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    uint8_t buffer[65536];
    ChroTimer timer{"tm"};
    while (true) {
        const char* proto_str = nullptr;
        char src[INET_ADDRSTRLEN] = {};
        char dst[INET_ADDRSTRLEN] = {};
        std::optional<uint16_t> sport;
        std::optional<uint16_t> dport;
        std::string flag = "";
        size_t payload_len = 0;
        bool syn_only = false;
        sockaddr_ll form;
        socklen_t form_len = sizeof(form);

        ssize_t len = recvfrom(fd, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&form), &form_len);
        if (len < 0) {
            perror("recv");
            break;
        }
        // 아웃바운드 패킷은 스킵
        if(form.sll_pkttype == PACKET_OUTGOING) {
            continue;
        }

        if (len < static_cast<ssize_t>(sizeof(ethhdr) + sizeof(iphdr))) {
            continue;
        }

        // 4. Ethernet 헤더 해석, IPv4만 통과
        const ethhdr* eth = reinterpret_cast<const ethhdr*>(buffer);
        if (ntohs(eth->h_proto) != ETH_P_IP) {
            continue;
        }

        // 5. Ethernet 헤더 바로 뒤가 IP 헤더
        const iphdr* ip = reinterpret_cast<const iphdr*>(buffer + sizeof(ethhdr));
        size_t frame_len = static_cast<size_t>(len);
        size_t ip_header_len = static_cast<size_t>(ip->ihl) * 4;
        
        // 패킷 유효성 검사
        // ihl : IP헤더길이. 4바이트 배수로 표현하게 만들었음(iph필드가 4비트밖에 안되서 0~15밖에 표현 못함)
        if(ip->ihl < 5 || frame_len < sizeof(ethhdr) + ip_header_len) {
            continue;
        }
        size_t tot_len = ntohs(ip->tot_len);
        if(tot_len < ip_header_len || tot_len > frame_len - sizeof(ethhdr)) {
            continue;
        }
        size_t l4offset = sizeof(ethhdr) + ip_header_len;
        const uint8_t* l4 = buffer + l4offset;
        size_t l4avail = frame_len - l4offset;

        switch (ip->protocol)
        {
        case IPPROTO_TCP: {
#ifndef u_TCP
continue;
#endif
            if(l4avail < sizeof(tcphdr)) {
                continue;
            }
            proto_str = "TCP";
            flag += "[";
            const tcphdr* tcp = reinterpret_cast<const tcphdr*>(l4);
            size_t tcp_header_len = static_cast<size_t>(tcp->doff) * 4;
            if(tcp_header_len < sizeof(tcphdr) || l4avail < tcp_header_len) {
                continue;
            }
            if(tot_len < ip_header_len + tcp_header_len) {
                continue;
            }
            if(tcp->syn) flag += "S";
            if(tcp->fin) flag += "F";
            if(tcp->rst) flag += "R";
            if(tcp->ack) flag += ".";
            flag += "] ";
            syn_only = tcp->syn && !tcp->ack;   // SYN만 있는 패킷인지 확인
            sport = ntohs(tcp->th_sport);
            dport = ntohs(tcp->th_dport);
            payload_len = tot_len - ip_header_len - tcp_header_len;
            break;
        }
        
        case IPPROTO_UDP: {
#ifndef u_UDP
continue;
#endif
            if(l4avail < sizeof(udphdr)) {
                continue;
            }
            if(tot_len < ip_header_len + sizeof(udphdr)) {
                continue;
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
continue;
#endif
            if(l4avail < sizeof(icmphdr)) {
                continue;
            }
            if(tot_len < ip_header_len + sizeof(icmphdr)) {
                continue;
            }
            proto_str = "ICMP";
            const icmphdr* icmp = reinterpret_cast<const icmphdr*>(l4);
            if(icmp->type == ICMP_ECHO) {
                flag = "echo request ";
            } else if (icmp->type == ICMP_ECHOREPLY) {
                flag = "echo reply ";
            } else {
                flag = "type:" + std::to_string(icmp->type) + " ";
            }
            payload_len = tot_len - ip_header_len - sizeof(icmphdr);
            break;
        }
        default:
            continue;
            break;
        }

        // SSH 연결은 무시
        if(sport == 22 || dport == 22) {
            continue;
        }


        // 6. IP 주소를 문자열로 변환
        inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
        inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));

#ifdef EXCEPT_SELF
        if((std::strncmp(src, "127.0.0.1", sizeof("127.0.0.1")) == 0) && 
            (std::strncmp(dst, "127.0.0.1", sizeof("127.0.0.1")) == 0)) {
            continue;
        } 
#endif

        // ip목록 추가/관리
        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
        std::unordered_map<uint32_t, ScanTracker>::iterator it = history.find(ip->saddr);
        if(it == history.end()) {
            it = history.try_emplace(ip->saddr).first;
            it->second.watch_start = now;
            it->second.watch_last = now;
            inet_ntop(AF_INET, &ip->saddr, it->second.src, sizeof(it->second.src));
            // std::cout << "[new]" << it->second << "\n";
        } else {
            ScanTracker& target = it->second;
            if(steady_diff(target.watch_last, now) > DURATION) {
                // std::cout << "[deleted]" << target << "\n";
                history.erase(it);
                it = history.end();
            } else {
                // std::cout << target << "\n";
                target.watch_last = now;
            }
        }

        // 포트 검사
        if(it != history.end() && syn_only) {
            ScanTracker& target = it->second;
            if(steady_diff(target.watch_start, now) > PORTCHECKDURATION_S) {
                target.ports.clear();
                target.watch_start = now;
                target.is_alert = false;
            }
            target.ports.insert(*dport);
            if(dport.has_value() && target.ports.size() > KPORTTHRESHOLD && !target.is_alert) {
                target.is_alert = true;
                std::cout << "[!!SCAN ALERT!!] " << target.src << " ports:" 
                << target.ports.size() << "\n";
            }
        }

        // 3초마다 전체 검사
        if(timer.duration() >= 3 ) {
            // std::cout << "---------------------[list]---------------------\n";
            std::unordered_map<uint32_t, ScanTracker>::iterator target_it = history.begin();
            while(target_it != history.end()) {
                if(it != target_it && steady_diff(target_it->second.watch_last, now) > DURATION) {
                    // std::cout << "[deleted]" << target_it->second << "\n";
                    target_it = history.erase(target_it);
                } else {
                    // std::cout << target_it->second << "\n";
                    target_it++;
                }
            }
            // std::cout << "------------------------------------------------\n";
            timer.reset();
        }


        // 7. 출력 (protocol: 1=ICMP, 6=TCP, 17=UDP)
        // if(sport.has_value() && dport.has_value()) {
        //     printf("%s src=%s:%u -> dst=%s:%u %s%zu bytes\n",
        //         proto_str,
        //         src,
        //         static_cast<unsigned int>(*sport),
        //         dst,
        //         static_cast<unsigned int>(*dport),
        //         flag.c_str(),
        //         payload_len
        //     );
        // } else {
        //     printf("%s src=%s -> dst=%s %s%zu bytes\n",
        //         proto_str,
        //         src,
        //         dst,
        //         flag.c_str(),
        //         payload_len
        //     );
        // }
        
    }

    close(fd);
    return 0;
}