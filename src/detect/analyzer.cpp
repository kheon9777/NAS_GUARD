#include "detect/analyzer.h"

#include <chrono>

#include "packet/ip_ICMP_RS.h"
#include "packet/ip_TCP_RS.h"

namespace RS::detect {
analyzer::analyzer(const config& con) : rate_tcp_(con.tcp_rate), rate_icmp_(con.icmp_rate) {
}
void analyzer::reconfigure(const config& con) {
    rate_tcp_.reconfigure(con.tcp_rate);
    rate_icmp_.reconfigure(con.icmp_rate);
}
// 프로토콜별로 "셀 패킷"만 골라 감지기에 넘긴다
verdict analyzer::analyze(const packet::ip_RS& ip) {
    time_point now = std::chrono::steady_clock::now();
    switch(ip.proto()) {
    case packet::ip_RS_type::TCP: {
        auto& tcp = static_cast<const packet::ip_TCP_RS&>(ip);
        if(tcp.is_flag_no_ACK()) {	// 맺어진 연결의 패킷은 제외
            return rate_tcp_.feed(ip.src(), now);
        }
        return verdict::ok;
    }
    case packet::ip_RS_type::ICMP: {
        auto& icmp = static_cast<const packet::ip_ICMP_RS&>(ip);
        if(icmp.is_echo_request()) {	// reply 등 응답류는 제외
            return rate_icmp_.feed(ip.src(), now);
        }
        return verdict::ok;
    }
    default:
        return verdict::ok;
    }
}
void analyzer::expire(time_point now) {
    rate_tcp_.expire(now);
    rate_icmp_.expire(now);
}
size_t analyzer::tracked() const {
    return rate_tcp_.tracked() + rate_icmp_.tracked();
}
}
