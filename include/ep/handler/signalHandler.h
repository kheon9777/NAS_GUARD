#ifndef SIGNALHANDLER_H
#define SIGNALHANDLER_H

#include "block/blocker.h"
#include "ep/handler/eventHandler.h"
#include "ep/reloader.h"

namespace RS::ep {
/**
 * SIGTERM, SIGINT : 루프 종료. SIGCHLD : nft 자식 회수. SIGHUP : reloader::reload() (설정, 화이트리스트 리로드).
 * 생성자에서 시그널을 막으므로(sigprocmask) 스레드를 만드는 객체보다 먼저 만들어야 한다.
 */
class signalHandler : public eventHandler {
private:
    int fd_;
    block::blocker& blocker_;
    reloader& reloader_;
public:
    signalHandler(block::blocker& blocker, reloader& rl);	// 시그널을 막고 signalfd를 만든다. 실패하면 std::system_error
    ~signalHandler();	// signalfd를 닫는다
    int fd() const override;
    eventHandlerResult on_readable() noexcept override;	// 시그널 하나 읽어 종류별로 처리
};
}

#endif
