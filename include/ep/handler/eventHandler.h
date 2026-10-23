#ifndef EVENTHANDLER_H
#define EVENTHANDLER_H

namespace RS::ep {
// on_readable() 결과. error는 복구 불가(fd가 망가짐 등)라는 뜻이고 루프가 종료된다
enum class eventHandlerResult : int {
    ok, error
};

/**
 * epoll에 등록되는 입력 소스 하나. fd()가 감시할 fd, on_readable()이 읽을 수 있을 때 할 일.
 * on_readable()은 noexcept: 루프 경로라 예외를 쓰지 않고 반환 코드로 알린다. 복사 불가 (fd를 소유하므로).
 */
class eventHandler {
public:
    virtual ~eventHandler() = default;
    virtual int fd() const = 0;
    virtual eventHandlerResult on_readable() noexcept = 0;
    eventHandler(const eventHandler&) = delete;
    eventHandler& operator=(const eventHandler&) = delete;
protected:
    eventHandler() = default;
};

// sample
// class UartHandler : public EventHandler {
// private:
//     int fd_;
//     int val_;
// public:
//     int fd() const override {
//         return fd_;
//     }
//     int on_readable() override {

//     }
// }
}

#endif
