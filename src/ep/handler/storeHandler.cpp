#include "ep/handler/storeHandler.h"

#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <cstring>

#include "util/logger.h"

namespace RS::ep {
storeHandler::storeHandler(store::database& db) : db_(db) {
    util::info("storeHandler created");
}
int storeHandler::fd() const {
    return db_.done_fd();
}
eventHandlerResult storeHandler::on_readable() noexcept {
    uint64_t count = 0;
    if(read(db_.done_fd(), &count, sizeof(count)) != static_cast<ssize_t>(sizeof(count))) {
        if(errno == EAGAIN) return eventHandlerResult::ok;	// 다른 깨어남과 겹쳐 이미 비워진 경우
        util::error("storeHandler::on_readable > read: ", std::strerror(errno));
        return eventHandlerResult::error;	// fd가 망가지면 계속 깨어나므로 치명적으로 본다
    }
    db_.reap();
    return eventHandlerResult::ok;
}
}
