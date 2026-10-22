#ifndef SIGNALHANDLER_H
#define SIGNALHANDLER_H

#include "ep/handler/eventHandler.h"

namespace RS::ep {
class signalHandler : public eventHandler{
private:
    int fd_;
public:
    signalHandler();
    ~signalHandler();
    int fd() const override;
    eventHandlerResult on_readable() noexcept override;
};
}

#endif
