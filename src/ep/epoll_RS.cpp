#include <sys/epoll.h>
#include <unistd.h>
#include <vector>
#include <memory>

#include <cerrno>
#include <system_error>

#include "ep/handler/eventHandler.h"
#include "ep/epoll_RS.h"
#include "util/logger.h"

namespace RS::ep {
epoll_RS::epoll_RS(int timeout) : fd_(epoll_create1(0)), timeout_(timeout)
{
    if(timeout <= 0) {
        throw std::system_error(errno, std::generic_category(), "epoll_RS > timeout should be over 0");
    }
    if(fd_ == -1) {
        throw std::system_error(errno, std::generic_category(), "epoll_RS > construc > epoll_create1");
    }
    RS::util::logger("ep opened");
}

epoll_RS::~epoll_RS()
{
    if(fd_ >= 0) {
        close(fd_);
        RS::util::logger("ep closed");
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
        throw std::system_error(errno, std::generic_category(), "epoll_RS > wait > epoll_wait");
    } else if (ret == 0) {
        return result::timeout;
    } else {
        do_task(ret);
        return result::has_event;
    }
}

void epoll_RS::do_task(int event_count) {
    for(int i = 0; i < event_count; i++) {
        eventHandler* handler = static_cast<eventHandler*>(event_list_[i].data.ptr);
        handler->on_readable();
    }
}

}