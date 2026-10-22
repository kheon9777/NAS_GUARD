#ifndef EPOLL_RS_H
#define EPOLL_RS_H

#include <sys/epoll.h>
#include <memory>
#include <vector>

#include "ep/handler/eventHandler.h"

#define MAX_EVENTS 20

namespace RS::ep {
class epoll_RS {
private:
    std::vector<std::unique_ptr<eventHandler>> handlers_;
    int fd_;
    int timeout_;
    epoll_event event_list_[MAX_EVENTS] = {};
    bool do_task(int event_count);      // 핸들러가 error를 돌려주면 false
public:
    /**
     * timeout : ms단위, 무조건 0이상
     */
    epoll_RS(int timeout);
    ~epoll_RS();
    enum class result : int {
        timeout,
        has_event,
        interrupted,
        error           // epoll_wait 실패 (EINTR 제외). errno 보존됨
    };
    int fd() const;
    eventHandler& add(std::unique_ptr<eventHandler> handler);
    result wait();
};
}
#endif
