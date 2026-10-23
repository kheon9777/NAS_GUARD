#include "ep/handler/signalHandler.h"

#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <cerrno>
#include <system_error>

#include "block/blocker.h"
#include "ep/epoll_loop.h"
#include "util/logger.h"

namespace RS::ep {
signalHandler::signalHandler(block::blocker& blocker, reloader& rl) : fd_(-1), blocker_(blocker), reloader_(rl) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGHUP);	// 설정, 화이트리스트 리로드
    sigaddset(&mask, SIGINT);	// Ctrl+C도 정상 종료 경로로 (소멸자 -> nft 테이블 삭제)
    sigaddset(&mask, SIGCHLD);	// nft 자식 프로세스 종료 통지
    if(sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        throw std::system_error(errno, std::generic_category(), "signalHandler > construc > sigprocmask");
    }
    if((fd_ = signalfd(-1, &mask, 0)) == -1) {
        throw std::system_error(errno, std::generic_category(), "signalHandler > construc > signalfd");
    }
    util::info("signalHandler created");
}

signalHandler::~signalHandler() {
    if(fd_ >= 0) {
        close(fd_);
    }
    util::info("signalHandler closed");
}

int signalHandler::fd() const {
    return fd_;
}

eventHandlerResult signalHandler::on_readable() noexcept {
    signalfd_siginfo fdsi;
    ssize_t res = read(fd_, &fdsi, sizeof(fdsi));
    if(res != sizeof(fdsi)) {
        RS::util::error("signalHandler::on_readable > read");
        return eventHandlerResult::error;
    }
    switch(fdsi.ssi_signo) {
    case SIGTERM:
    case SIGINT: {
        RS::util::info(fdsi.ssi_signo == SIGTERM ? "SIGTERM" : "SIGINT", " detected, stopping");
        set_g_working(false);
        break;
    }
    case SIGHUP:
        RS::util::info("SIGHUP detected, reloading");
        reloader_.reload();
        break;
    case SIGCHLD:
        blocker_.reap();
        break;
    default:
        break;
    }
    return eventHandlerResult::ok;
}
}
