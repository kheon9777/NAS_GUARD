#include "ep/handler/timerHandler.h"

#include <sys/timerfd.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <system_error>

#include "packet/mac.h"
#include "store/device_store.h"
#include "util/logger.h"
#include "util/procinfo.h"

namespace RS::ep {
timerHandler::timerHandler(std::chrono::seconds interval, unsigned long mem_log_every, block::blocker& blocker,
detect::analyzer& anyz, detect::device_tracker& devices, store::database& db)
: fd_(-1), blocker_(blocker), anyz_(anyz), devices_(devices), db_(db), mem_log_every_(mem_log_every) {
    // CLOCK_MONOTONIC : 시스템 시각이 바뀌어도 간격이 유지됨. steady_clock과 같은 기준
    if((fd_ = timerfd_create(CLOCK_MONOTONIC, 0)) == -1) {
        throw std::system_error(errno, std::generic_category(), "timerHandler > construc > timerfd_create");
    }
    itimerspec spec = {};
    spec.it_value.tv_sec = interval.count();	// 첫 만료까지
    spec.it_interval.tv_sec = interval.count();	// 이후 반복 간격 (0이면 한 번만)
    if(timerfd_settime(fd_, 0, &spec, nullptr) == -1) {
        close(fd_);
        throw std::system_error(errno, std::generic_category(), "timerHandler > construc > timerfd_settime");
    }
    util::info("timerHandler created");
}
bool timerHandler::set_interval(std::chrono::seconds interval) {
    itimerspec spec = {};
    spec.it_value.tv_sec = interval.count();
    spec.it_interval.tv_sec = interval.count();
    if(timerfd_settime(fd_, 0, &spec, nullptr) == -1) {
        util::error("timerHandler::set_interval > timerfd_settime: ", std::strerror(errno));
        return false;
    }
    return true;
}
timerHandler::~timerHandler() {
    if(fd_ >= 0) {
        close(fd_);
    }
    util::info("timerHandler closed");
}
int timerHandler::fd() const {
    return fd_;
}
eventHandlerResult timerHandler::on_readable() noexcept {
    uint64_t expirations = 0;
    if(read(fd_, &expirations, sizeof(expirations)) != sizeof(expirations)) {
        util::error("timerHandler::on_readable > read");
        return eventHandlerResult::error;
    }
    auto now = std::chrono::steady_clock::now();
    blocker_.expire(now);
    anyz_.expire(now);
    util::log_flush();	// stdout 버퍼를 주기적으로 비움. 서비스에서는 stdout이 파이프라 이게 없으면 journal에 늦게 나옴
    util::log_rotate_if_needed();	// 날이 바뀌면 새 날짜 로그 파일로. 파일을 바꾸는 유일한 자리 (메인 스레드)

    // 오래 안 보인 장비 제거 -> DB에서도 삭제
    int64_t now_s = static_cast<int64_t>(std::time(nullptr));
    scratch_.clear();
    devices_.expire(now_s, scratch_);
    for(const detect::device& d : scratch_) {
        char mac_buf[packet::MAC_STR_LEN];
        packet::mac_to_str(d.mac, mac_buf);
        util::info("[device] gone ", mac_buf, " (last seen ", now_s - d.last_seen, "s ago)");
        store::device_delete_async(db_, d.mac);
        store::device_event_async(db_, "device_gone", d.ip, d.mac, 0, now_s);
    }

    // 메모리 사용량. 첫 틱에 기준값 한 번, 이후 주기적으로. tracked/blocked가 계속 늘면 만료가 안 되는 것
    ticks_ += expirations;
    if(ticks_ == expirations || ticks_ % mem_log_every_ < expirations) {
        util::info("[mem] rss=", util::rss_kb(), "KB tracked=", anyz_.tracked(),
                   " blocked=", blocker_.blocked(), " pending=", blocker_.pending(),
                   " devices=", devices_.size(), " db_queue=", db_.pending());
        // 같은 주기로 장비 last_seen/ip 변경분을 DB에 반영 (패킷마다 쓰지 않도록 모아서)
        scratch_.clear();
        devices_.take_dirty(scratch_);
        for(const detect::device& d : scratch_) {
            store::device_update_async(db_, d);
        }
    }
    return eventHandlerResult::ok;
}

}
