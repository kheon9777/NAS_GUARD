#include "scnet/rawsock.h"

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <system_error>

#include "scnet/parser.h"
#include "util/logger.h"

namespace RS::scnet {

int ready_rawsock() {
    // 1. 모든 패킷을 받는 raw 소켓 열기
    // AF_PACKET : 네트워크 층 가장 아래, 랜카드 바로 위에서 패킷을 받겠다.
    // SOCK_RAW : Ethernet 헤더를 포함한 프레임 다 받는다.
    // 세 번째 인자 : 패킷 거르는 필터링, ETH_P_ALL은 다 받는다는 소리
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(fd < 0) {
        throw std::system_error(errno, std::generic_category(), "ready_rawsock > socket");
    }
    return fd;
}

void close_rawsock(int fd) {
    close(fd);
}

/**
 * rescode 정상:frame_RS(ip_RS 또는 arp_RS),code=0, 에러:nullptr,code<0, 제외(스킵):nullptr,code>0
 */
std::unique_ptr<packet::frame_RS> rawsock_recv(int fd, int& rescode) {
    uint8_t buffer[65536];
    sockaddr_ll form;
    socklen_t form_len = sizeof(form);
    rescode = 0;

    ssize_t len = recvfrom(fd, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&form), &form_len);
    if(len < 0) {
        int err = errno;	// 로그 출력이 errno를 건드릴 수 있어 보존
        util::warn("rawsock_recv > recvfrom: ", std::strerror(err));
        errno = err;	// 호출자가 errno로 치명 여부를 판단
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

    return parse_frame(buffer, static_cast<size_t>(len), rescode);
}

}
