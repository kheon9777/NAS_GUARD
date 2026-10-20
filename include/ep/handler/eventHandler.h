#ifndef EVENTHANDLER_H
#define EVENTHANDLER_H

namespace RS::ep {
enum class eventHandlerResult : int {
    ok, error
};

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