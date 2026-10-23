#ifndef RAWSOCKHANDLER_H
#define RAWSOCKHANDLER_H

#include "block/blocker.h"
#include "block/whitelist.h"
#include <cstdint>

#include "detect/analyzer.h"
#include "detect/device_tracker.h"
#include "ep/handler/eventHandler.h"
#include "store/database.h"

namespace RS::ep {
/**
 * raw 소켓(AF_PACKET)에서 프레임을 받아 장비 감지, 차단 확인, 화이트리스트, 감지기, 차단 순으로 처리한다.
 * 장비 감지는 화이트리스트보다 앞에 있어야 한다 (집 LAN이 화이트리스트라 뒤에 두면 장비가 하나도 안 보임).
 */
class rawsockHandler : public eventHandler {
private:
    int fd_;
    detect::analyzer& anyz_;
    block::whitelist& wlist_;
    block::blocker& blocker_;
    detect::device_tracker& devices_;
    store::database& db_;
    void track_device(uint64_t mac, uint32_t ip) noexcept;	// ARP sender로 장비 목록 갱신 + 이벤트 로그/DB
public:
    rawsockHandler(detect::analyzer& anyz, block::whitelist& wlist, block::blocker& blocker,
        detect::device_tracker& devices, store::database& db);	// 소켓을 연다. 실패하면 std::system_error
    ~rawsockHandler() override;	// 소켓을 닫는다
    int fd() const override;
    eventHandlerResult on_readable() noexcept override;	// 프레임 하나 처리. 소켓이 망가진 경우만 error
};
}

#endif
