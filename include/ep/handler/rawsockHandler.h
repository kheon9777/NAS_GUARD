#ifndef RAWSOCKHANDLER_H
#define RAWSOCKHANDLER_H

#include "ep/handler/eventHandler.h"

namespace RS::ep {
    class rawsockHandler : public eventHandler {
    private:
        int fd_;
        /* data */
    public:
        rawsockHandler();
        ~rawsockHandler() override;
        int fd() const override;
        eventHandlerResult on_readable() noexcept override;
    };
}

#endif