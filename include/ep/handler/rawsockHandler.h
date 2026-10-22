#ifndef RAWSOCKHANDLER_H
#define RAWSOCKHANDLER_H

#include "block/blocker.h"
#include "block/whitelist.h"
#include "detect/analyzer.h"
#include "ep/handler/eventHandler.h"

namespace RS::ep {
class rawsockHandler : public eventHandler {
private:
    int fd_;
    detect::analyzer& anyz_;
    block::whitelist& wlist_;
    block::blocker& blocker_;
public:
    rawsockHandler(detect::analyzer& anyz, block::whitelist& wlist, block::blocker& blocker);
    ~rawsockHandler() override;
    int fd() const override;
    eventHandlerResult on_readable() noexcept override;
};
}

#endif
