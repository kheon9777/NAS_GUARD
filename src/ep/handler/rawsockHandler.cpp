#include "ep/handler/rawsockHandler.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <system_error>

#include "block/blocker.h"
#include "block/whitelist.h"
#include "detect/analyzer.h"
#include "packet/ip_RS.h"
#include "scnet/rawsock.h"
#include "util/logger.h"

namespace RS::ep {
rawsockHandler::rawsockHandler(detect::analyzer& anyz, block::whitelist& wlist, block::blocker& blocker)
: fd_(-1), anyz_(anyz), wlist_(wlist), blocker_(blocker) {
    if((fd_ = scnet::ready_rawsock()) == -1) {
        throw std::system_error(errno, std::generic_category(), "rawsockHandler > construc > socket");
    }
    util::logger("rawsockHandler created");
}
rawsockHandler::~rawsockHandler() {
    scnet::close_rawsock(fd_);
}
int rawsockHandler::fd() const {
    return fd_;
}
eventHandlerResult rawsockHandler::on_readable() noexcept {
    int rescode = 0;
    // return :
    //  (정상)ip_RS,code=0, (에러)nullptr,code<0, (제외, 스킵):nullptr,code>0
    std::unique_ptr<packet::ip_RS> target = scnet::rawsock_recv(fd_, rescode);
    if(rescode == -2) {                                                 // recvfrom 실패
        if(errno == EBADF || errno == ENOTSOCK || errno == EFAULT) {    // fd 자체가 망가짐 -> 복구 불가
            util::logger("rawsockHandler > socket broken: ", std::strerror(errno));
            return eventHandlerResult::error;
        }
        return eventHandlerResult::ok;                                  // EAGAIN, ENOBUFS 등 일시적
    }
    if(rescode != 0) return eventHandlerResult::ok;                     // 스킵 / 패킷 하나 이상

    auto now = std::chrono::steady_clock::now();
    uint32_t src = target->src();

    // 이미 차단된 IP는 분석하지 않음 (nft 재실행 / 기록 누적 방지)
    if(blocker_.is_blocked(src, now)) {
        return eventHandlerResult::ok;
    }

    // whitelist
    if(wlist_.contains(src)) {
        return eventHandlerResult::ok;
    }
    if(wlist_.contains_custom_filter(*target)) {
        return eventHandlerResult::ok;
    }

    // std::cout << *target << "\n";

    detect::verdict res_v = anyz_.analyze(*target);
    if(res_v != detect::verdict::ok) {
        char ip_buf[INET_ADDRSTRLEN];           // std::string 할당 없이 스택 버퍼로
        inet_ntop(AF_INET, &src, ip_buf, sizeof(ip_buf));
        util::logger("[detect] ", ip_buf, " verdict=", static_cast<int>(res_v));
        blocker_.block(src, now);

        // TODO(store) : store_.record(src, res_v, now);
    }
    return eventHandlerResult::ok;
}
}
