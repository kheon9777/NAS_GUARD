#include "scnet/parser.h"

#include <linux/if_ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <new>

#include "packet/arp_RS.h"
#include "packet/ip_ICMP_RS.h"
#include "packet/ip_TCP_RS.h"
#include "packet/ip_UDP_RS.h"

namespace RS::scnet {

std::unique_ptr<packet::frame_RS> parse_frame(const uint8_t* frame, size_t len, int& rescode) {
    rescode = 0;

    if(len < sizeof(ethhdr)) {
        rescode = -3;
        return nullptr;
    }
    const ethhdr* eth = reinterpret_cast<const ethhdr*>(frame);
    uint16_t eth_type = ntohs(eth->h_proto);

    // ARP: 장비 감지용. sender(MAC, IP)만 쓴다
    if(eth_type == ETH_P_ARP) {
        if(len < sizeof(ethhdr) + sizeof(ether_arp)) {
            rescode = -12;
            return nullptr;
        }
        const ether_arp* arp = reinterpret_cast<const ether_arp*>(frame + sizeof(ethhdr));
        if(ntohs(arp->arp_hrd) != ARPHRD_ETHER || ntohs(arp->arp_pro) != ETH_P_IP
        || arp->arp_hln != 6 || arp->arp_pln != 4) {	// 이더넷 + IPv4 ARP만
            rescode = -13;
            return nullptr;
        }
        std::unique_ptr<packet::frame_RS> res(new(std::nothrow) packet::arp_RS{arp});
        if(!res) {
            rescode = -11;
            return nullptr;
        }
        res->set_src_mac(eth->h_source);
        return res;
    }

    // 4. IPv4만 통과
    if(eth_type != ETH_P_IP) {
        rescode = -4;
        return nullptr;
    }
    if(len < sizeof(ethhdr) + sizeof(iphdr)) {
        rescode = -3;
        return nullptr;
    }

    // 5. Ethernet 헤더 바로 뒤가 IP 헤더
    const iphdr* ip = reinterpret_cast<const iphdr*>(frame + sizeof(ethhdr));
    size_t ip_header_len = static_cast<size_t>(ip->ihl) * 4;

    // 패킷 유효성 검사
    // ihl : IP헤더길이. 4바이트 배수로 표현하게 만들었음(iph필드가 4비트밖에 안되서 0~15밖에 표현 못함)
    if(ip->ihl < 5 || len < sizeof(ethhdr) + ip_header_len) {
        rescode = -5;
        return nullptr;
    }
    size_t tot_len = ntohs(ip->tot_len);
    if(tot_len < ip_header_len || tot_len > len - sizeof(ethhdr)) {
        rescode = -6;
        return nullptr;
    }
    size_t l4offset = sizeof(ethhdr) + ip_header_len;
    const uint8_t* l4 = frame + l4offset;
    size_t l4avail = len - l4offset;

    int get_ip_resultcode = 0;
    std::unique_ptr<packet::ip_RS> target = get_ip_RS(ip, l4, l4avail, ip_header_len, tot_len, get_ip_resultcode);
    if(target == nullptr) rescode = -7;
    if(get_ip_resultcode != 0) rescode = get_ip_resultcode;
    if(target) target->set_src_mac(eth->h_source);

    return target;
}

std::unique_ptr<packet::ip_RS> get_ip_RS(const iphdr* ip, const uint8_t* l4, const size_t l4avail,
const size_t ip_header_len, const size_t tot_len, int& rescode) {
    std::unique_ptr<packet::ip_RS>res(nullptr);
    rescode = 0;
    switch(ip->protocol) {
    case IPPROTO_TCP: {
        if(l4avail < sizeof(tcphdr)) {	// 길이 문제
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
        res.reset(new(std::nothrow) packet::ip_TCP_RS{ip, tcp});
        if(!res) {	// 메모리 할당 실패
            rescode = -11;
            break;
        }
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
        res.reset(new(std::nothrow) packet::ip_UDP_RS{ip, udp});
        if(!res) {
            rescode = -11;
            break;
        }
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
        res.reset(new(std::nothrow) packet::ip_ICMP_RS{ip, icmp});
        if(!res) {
            rescode = -11;
            break;
        }
        res->set_payload_len(tot_len - ip_header_len - sizeof(icmphdr));
        break;
    }
    }
    return res;
}

}
