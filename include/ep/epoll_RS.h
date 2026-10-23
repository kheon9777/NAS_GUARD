#ifndef EPOLL_RS_H
#define EPOLL_RS_H

#include <sys/epoll.h>
#include <memory>
#include <vector>

#include "ep/handler/eventHandler.h"
#include "settings.h"

namespace RS::ep {
/**
 * epoll 인스턴스 하나와 거기 등록된 핸들러들. add()로 소유권을 받고 wait()에서 이벤트가 온 핸들러의 on_readable()을 부른다.
 * 생성자와 add()는 초기화 단계라 std::system_error를 던진다. wait()는 루프 경로라 던지지 않고 result로 알린다.
 */
class epoll_RS {
private:
    std::vector<std::unique_ptr<eventHandler>> handlers_;
    int fd_;
    int timeout_;
    epoll_event event_list_[settings::MAX_EVENTS] = {};
    bool do_task(int event_count);	// 핸들러가 error를 돌려주면 false
public:
    /**
     * timeout : ms단위, 0보다 커야 함
     */
    epoll_RS(int timeout);
    ~epoll_RS();	// epoll fd를 닫고 핸들러들(unique_ptr)을 소멸
    enum class result : int {
        timeout,
        has_event,
        interrupted,
        error	// epoll_wait 실패 (EINTR 제외). errno 보존됨
    };
    int fd() const;	// epoll fd
    bool set_timeout(int timeout);	// 리로드. 0 이하면 거부하고 false
    eventHandler& add(std::unique_ptr<eventHandler> handler);	// 핸들러 fd를 EPOLLIN으로 등록하고 소유권을 가져감. 돌려주는 참조는 epoll_RS가 살아 있는 동안 유효
    result wait();	// timeout까지 기다렸다가 이벤트가 온 핸들러들을 실행. 핸들러가 error를 돌려주면 error
};
}
#endif
