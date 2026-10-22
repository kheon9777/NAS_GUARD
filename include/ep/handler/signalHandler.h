#ifndef SIGNALHANDLER_H
#define SIGNALHANDLER_H

#include "block/blocker.h"
#include "ep/handler/eventHandler.h"

namespace RS::ep {
class signalHandler : public eventHandler {
private:
    int fd_;
    block::blocker& blocker_;
public:
    explicit signalHandler(block::blocker& blocker);
    ~signalHandler();
    int fd() const override;
    eventHandlerResult on_readable() noexcept override;
};
}

#endif
