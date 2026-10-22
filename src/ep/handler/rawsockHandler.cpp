#include "ep/handler/rawsockHandler.h"

#include <cerrno>
#include <memory>
#include <system_error>

#include "block/whitelist.h"
#include "detect/analyzer.h"
#include "packet/ip_RS.h"
#include "scnet/rawsock.h"
#include "util/logger.h"

namespace RS::ep {
rawsockHandler::rawsockHandler(detect::analyzer& anyz, block::whitelist& wlist) : fd_(-1), anyz_(anyz), wlist_(wlist) {    // TODO(block) : blocker 생성자 주입
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
    if(rescode != 0) return eventHandlerResult::ok;

    // TODO(block) : 이미 차단된 IP는 분석하지 않음 (nft 재실행 / 기록 누적 방지)
    // if(blocker_.is_blocked(target->src())) return eventHandlerResult::ok;

    // whitelist
    if(wlist_.contains(target->src())) {
        return eventHandlerResult::ok;
    }
    if(wlist_.contains_custom_filter(*target)) {
        return eventHandlerResult::ok;
    }

    std::cout << *target << "\n";

    detect::verdict res_v = anyz_.analyze(*target);
    if(res_v != detect::verdict::ok) {
        util::logger("[detect] ", target->src_str(), " verdict=", static_cast<int>(res_v));

        // TODO(block) : blocker_.block(target->src(), res_v);
        // TODO(store) : store_.record(target->src(), res_v, now);
    }
    return eventHandlerResult::ok;
}
}
