#include "ep/handler/signalHandler.h"

#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <cerrno>
#include <system_error>

#include "ep/epoll_loop.h"
#include "util/logger.h"

namespace RS::ep {
signalHandler::signalHandler() : fd_(-1) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGHUP);
    if(sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        throw std::system_error(errno, std::generic_category(), "signalHandler > construc > sigprocmask");
    }
    if((fd_ = signalfd(-1, &mask, 0)) == -1) {
        throw std::system_error(errno, std::generic_category(), "signalHandler > construc > signalfd");
    }
    util::logger("signalHandler created");
}

signalHandler::~signalHandler() {
    if(fd_ >= 0) {
        close(fd_);
    }
    util::logger("signalHandler closed");
}

int signalHandler::fd() const {
    return fd_;
}

eventHandlerResult signalHandler::on_readable() noexcept {
    signalfd_siginfo fdsi;
    ssize_t res = read(fd_, &fdsi, sizeof(fdsi));
    if(res != sizeof(fdsi)) {
        RS::util::logger("signalHandler::on_readable > read");
        return eventHandlerResult::error;
    }
    switch(fdsi.ssi_signo) {
    case SIGTERM: {
        RS::util::logger("sigterm detected!!!");
        set_g_working(false);
        break;
    }
    case SIGHUP:
        // TODO : sighup
        break;
    default:
        break;
    }
    return eventHandlerResult::ok;
}
}
