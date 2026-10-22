#ifndef RAWSOCKHANDLER_H
#define RAWSOCKHANDLER_H

#include "detect/analyzer.h"
#include "ep/handler/eventHandler.h"
#include "block/whitelist.h"

namespace RS::ep {
class rawsockHandler : public eventHandler {
private:
    int fd_;
    detect::analyzer& anyz_;
    block::whitelist& wlist_;
public:
    explicit rawsockHandler(detect::analyzer& anyz, block::whitelist& wlist);
    ~rawsockHandler() override;
    int fd() const override;
    eventHandlerResult on_readable() noexcept override;
};
}

#endif
