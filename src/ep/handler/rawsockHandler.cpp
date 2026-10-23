#include "ep/handler/rawsockHandler.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <memory>
#include <system_error>

#include "block/blocker.h"
#include "block/whitelist.h"
#include "detect/analyzer.h"
#include "packet/arp_RS.h"
#include "packet/frame_RS.h"
#include "packet/ip_RS.h"
#include "packet/mac.h"
#include "scnet/rawsock.h"
#include "store/block_store.h"
#include "store/device_store.h"
#include "util/logger.h"

namespace RS::ep {
rawsockHandler::rawsockHandler(detect::analyzer& anyz, block::whitelist& wlist, block::blocker& blocker,
detect::device_tracker& devices, store::database& db)
: fd_(-1), anyz_(anyz), wlist_(wlist), blocker_(blocker), devices_(devices), db_(db) {
    if((fd_ = scnet::ready_rawsock()) == -1) {
        throw std::system_error(errno, std::generic_category(), "rawsockHandler > construc > socket");
    }
    util::info("rawsockHandler created");
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
    //  (정상)frame_RS,code=0, (에러)nullptr,code<0, (제외, 스킵):nullptr,code>0
    std::unique_ptr<packet::frame_RS> frame = scnet::rawsock_recv(fd_, rescode);
    if(rescode == -2) {	// recvfrom 실패
        if(errno == EBADF || errno == ENOTSOCK || errno == EFAULT) {	// fd 자체가 망가짐 -> 복구 불가
            util::error("rawsockHandler > socket broken: ", std::strerror(errno));
            return eventHandlerResult::error;
        }
        return eventHandlerResult::ok;	// EAGAIN, ENOBUFS 등 일시적
    }
    if(rescode != 0) return eventHandlerResult::ok;	// 스킵 / 패킷 하나 이상

    // ARP는 장비 감지에만 쓴다. 화이트리스트보다 앞에 있어야 한다 (집 LAN이 화이트리스트라 뒤에 두면 장비가 하나도 안 보임)
    if(frame->is_type(packet::frame_type::arp)) {
        auto& arp = static_cast<const packet::arp_RS&>(*frame);
        util::debug(arp);
        track_device(arp.sender_mac(), arp.sender_ip());
        return eventHandlerResult::ok;
    }
    auto& target_ref = static_cast<const packet::ip_RS&>(*frame);
    const packet::ip_RS* target = &target_ref;

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

    util::debug(*target);	// 화이트리스트와 차단을 통과한 패킷. 기본 레벨에선 안 찍힘

    detect::verdict res_v = anyz_.analyze(*target);
    if(res_v != detect::verdict::ok) {
        char ip_buf[INET_ADDRSTRLEN];	// std::string 할당 없이 스택 버퍼로
        inet_ntop(AF_INET, &src, ip_buf, sizeof(ip_buf));
        util::info("[detect] ", ip_buf, " ", detect::verdict_name(res_v));
        blocker_.block(src, now);
        store::block_insert_async(db_, src, detect::verdict_name(res_v), static_cast<int64_t>(std::time(nullptr)));
    }
    return eventHandlerResult::ok;
}

// 새 장비는 바로 INSERT. last_seen 갱신은 timerHandler가 주기적으로 모아서 UPDATE.
// 스푸핑은 알람(error 로그 + 이벤트 행)만 하고 차단하지 않는다
void rawsockHandler::track_device(uint64_t mac, uint32_t ip) noexcept {
    int64_t now_s = static_cast<int64_t>(std::time(nullptr));
    detect::feed_result r = devices_.feed(mac, ip, now_s);
    if(!r.new_device && r.event == detect::device_event::none) return;

    char ip_buf[INET_ADDRSTRLEN];
    char mac_buf[packet::MAC_STR_LEN];
    char old_buf[packet::MAC_STR_LEN];
    inet_ntop(AF_INET, &ip, ip_buf, sizeof(ip_buf));
    packet::mac_to_str(mac, mac_buf);
    if(r.new_device) {
        util::info("[device] new ", mac_buf, " ip=", ip_buf);
        store::device_insert_async(db_, *r.dev);
        store::device_event_async(db_, "new_device", ip, 0, mac, now_s);
    }
    switch(r.event) {
    case detect::device_event::mac_changed:
        packet::mac_to_str(r.old_mac, old_buf);
        util::warn("[device] ip owner changed ", ip_buf, " ", old_buf, " -> ", mac_buf);
        store::device_event_async(db_, "mac_changed", ip, r.old_mac, mac, now_s);
        break;
    case detect::device_event::arp_spoof:
        packet::mac_to_str(r.old_mac, old_buf);
        util::error("[ALARM] arp spoof suspected ", ip_buf, " ", old_buf, " <-> ", mac_buf);
        store::device_event_async(db_, "arp_spoof", ip, r.old_mac, mac, now_s);
        break;
    default:
        break;
    }
}
}
