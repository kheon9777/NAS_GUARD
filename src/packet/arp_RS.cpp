#include "packet/arp_RS.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cstring>

#include "packet/mac.h"

namespace RS::packet {
arp_RS::arp_RS(const ether_arp* arp) : frame_RS(frame_type::arp), opcode_(ntohs(arp->arp_op)),
sender_mac_(mac_pack(arp->arp_sha)) {
    std::memcpy(&sender_ip_, arp->arp_spa, sizeof(sender_ip_));	// 4바이트 배열 그대로 네트워크 순서
    std::memcpy(&target_ip_, arp->arp_tpa, sizeof(target_ip_));
}
bool arp_RS::is_request() const {
    return opcode_ == ARPOP_REQUEST;
}
bool arp_RS::is_reply() const {
    return opcode_ == ARPOP_REPLY;
}
bool arp_RS::is_gratuitous() const {
    return sender_ip_ == target_ip_;
}
uint64_t arp_RS::sender_mac() const {
    return sender_mac_;
}
uint32_t arp_RS::sender_ip() const {
    return sender_ip_;
}
uint32_t arp_RS::target_ip() const {
    return target_ip_;
}
void arp_RS::print(std::ostream& os) const {
    char mac[MAC_STR_LEN];
    char sip[INET_ADDRSTRLEN];
    char tip[INET_ADDRSTRLEN];
    mac_to_str(sender_mac_, mac);
    inet_ntop(AF_INET, &sender_ip_, sip, sizeof(sip));
    inet_ntop(AF_INET, &target_ip_, tip, sizeof(tip));
    os << "ARP " << (is_request() ? "request" : is_reply() ? "reply" : "op?") << " " << sip << " (" << mac << ")"
       << (is_gratuitous() ? " gratuitous" : "") << " -> " << tip;
}
}
