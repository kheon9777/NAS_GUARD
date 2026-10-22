#include "ep/handler/timerHandler.h"

#include <sys/timerfd.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <system_error>

#include "util/logger.h"

namespace RS::ep {
timerHandler::timerHandler(std::chrono::seconds interval, block::blocker& blocker,
detect::analyzer& anyz) : fd_(-1), blocker_(blocker), anyz_(anyz) {
    // CLOCK_MONOTONIC : 시스템 시각이 바뀌어도 간격이 유지됨. steady_clock과 같은 기준
    if((fd_ = timerfd_create(CLOCK_MONOTONIC, 0)) == -1) {
        throw std::system_error(errno, std::generic_category(), "timerHandler > construc > timerfd_create");
    }
    itimerspec spec = {};
    spec.it_value.tv_sec = interval.count();        // 첫 만료까지
    spec.it_interval.tv_sec = interval.count();     // 이후 반복 간격 (0이면 한 번만)
    if(timerfd_settime(fd_, 0, &spec, nullptr) == -1) {
        close(fd_);
        throw std::system_error(errno, std::generic_category(), "timerHandler > construc > timerfd_settime");
    }
    util::logger("timerHandler created");
}
timerHandler::~timerHandler() {
    if(fd_ >= 0) {
        close(fd_);
    }
    util::logger("timerHandler closed");
}
int timerHandler::fd() const {
    return fd_;
}
eventHandlerResult timerHandler::on_readable() noexcept {
    uint64_t expirations = 0;
    if(read(fd_, &expirations, sizeof(expirations)) != sizeof(expirations)) {
        util::logger("timerHandler::on_readable > read");
        return eventHandlerResult::error;
    }
    auto now = std::chrono::steady_clock::now();
    blocker_.expire(now);
    anyz_.expire(now);
    return eventHandlerResult::ok;
}

}
