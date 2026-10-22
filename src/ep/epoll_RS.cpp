#include "ep/epoll_RS.h"

#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <system_error>

#include "util/logger.h"

namespace RS::ep {
epoll_RS::epoll_RS(int timeout) : fd_(epoll_create1(0)), timeout_(timeout) {
    if(timeout <= 0) {
        throw std::system_error(errno, std::generic_category(), "epoll_RS > timeout should be over 0");
    }
    if(fd_ == -1) {
        throw std::system_error(errno, std::generic_category(), "epoll_RS > construc > epoll_create1");
    }
    RS::util::logger("ep opened");
}

epoll_RS::~epoll_RS() {
    if(fd_ >= 0) {
        close(fd_);
        RS::util::logger("epoll_RS closed");
    }
}

int epoll_RS::fd() const {
    return fd_;
}

eventHandler& epoll_RS::add(std::unique_ptr<eventHandler> handler) {
    eventHandler* handler_ptr = handler.get();
    epoll_event epev = {};
    epev.events = EPOLLIN;
    epev.data.ptr = handler_ptr;
    handlers_.push_back(std::move(handler));

    if(epoll_ctl(fd_, EPOLL_CTL_ADD, handler_ptr->fd(), &epev) == -1) {
        throw std::system_error(errno, std::generic_category(), "epoll_RS > add > epoll_ctl");
    }
    return *(handlers_.back());
}

epoll_RS::result epoll_RS::wait() {
    int ret = epoll_wait(fd_, event_list_, sizeof(event_list_)/sizeof(epoll_event), timeout_);
    if(ret == -1) {
        if(errno == EINTR) { // ctrl_z
            return result::interrupted;
        }
        util::logger("epoll_RS > wait > epoll_wait: ", std::strerror(errno));
        return result::error;   // 루프 경로라 던지지 않고 반환
    } else if(ret == 0) {
        return result::timeout;
    } else {
        return do_task(ret) ? result::has_event : result::error;
    }
}

// 핸들러가 복구 불가(error)를 돌려주면 즉시 false. fd를 비우지 못한 채 계속 깨어나는 무한 반복을 막는다
bool epoll_RS::do_task(int event_count) {
    for(int i = 0; i < event_count; i++) {
        eventHandler* handler = static_cast<eventHandler*>(event_list_[i].data.ptr);
        if(handler->on_readable() == eventHandlerResult::error) {
            return false;
        }
    }
    return true;
}

}
