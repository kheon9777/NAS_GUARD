#ifndef TIMERHANDLER_H
#define TIMERHANDLER_H

#include <chrono>

#include "block/blocker.h"
#include "detect/analyzer.h"
#include "ep/handler/eventHandler.h"

namespace RS::ep {
/**
 * timerfd로 interval마다 깨어나 만료 정리(expire)를 돌린다.
 * epoll timeout은 패킷이 계속 들어오면 발생하지 않으므로, 주기 작업은 이 핸들러로 한다.
 */
class timerHandler : public eventHandler {
private:
    int fd_;
    block::blocker& blocker_;
    detect::analyzer& anyz_;
public:
    timerHandler(std::chrono::seconds interval, block::blocker& blocker, detect::analyzer& anyz);
    ~timerHandler() override;
    int fd() const override;
    eventHandlerResult on_readable() noexcept override;
};
}

#endif
