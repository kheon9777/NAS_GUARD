#ifndef TIMERHANDLER_H
#define TIMERHANDLER_H

#include <chrono>
#include <vector>

#include "block/blocker.h"
#include "detect/analyzer.h"
#include "detect/device_tracker.h"
#include "ep/handler/eventHandler.h"
#include "store/database.h"

namespace RS::ep {
/**
 * timerfd로 interval마다 깨어나 만료 정리(expire)를 돌린다.
 * epoll timeout은 패킷이 계속 들어오면 발생하지 않으므로, 주기 작업은 이 핸들러로 한다.
 * 장비 목록도 여기서 만료시키고(DB DELETE), 바뀐 last_seen을 mem_log 주기마다 모아서 DB에 쓴다.
 * 틱마다 log_flush()로 stdout 버퍼를 비우고, log_rotate_if_needed()로 날짜가 바뀌었으면 로그 파일을 바꾼다.
 */
class timerHandler : public eventHandler {
private:
    int fd_;
    block::blocker& blocker_;
    detect::analyzer& anyz_;
    detect::device_tracker& devices_;
    store::database& db_;
    std::vector<detect::device> scratch_;	// expire/take_dirty 결과를 받는 버퍼. 재사용해서 매번 할당하지 않음
    unsigned long ticks_ = 0;	// 만료 횟수 누적. 주기적 메모리 로그 간격 계산용
    unsigned long mem_log_every_;	// 메모리 로그 주기 (틱 수)
public:
    timerHandler(std::chrono::seconds interval, unsigned long mem_log_every, block::blocker& blocker, detect::analyzer& anyz,
        detect::device_tracker& devices, store::database& db);	// timerfd를 만들어 interval 주기로 건다. 실패하면 std::system_error
    bool set_interval(std::chrono::seconds interval);	// 리로드. 실패하면 로그 남기고 false (기존 주기 유지)
    void set_mem_log_every(unsigned long ticks) { mem_log_every_ = ticks; }	// 리로드. 메모리 로그 주기
    ~timerHandler() override;	// timerfd를 닫는다
    int fd() const override;
    eventHandlerResult on_readable() noexcept override;	// 틱마다 blocker, analyzer, device 만료. 주기적으로 [mem] 로그와 장비 DB 갱신
};
}

#endif
