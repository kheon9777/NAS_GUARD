#ifndef STOREHANDLER_H
#define STOREHANDLER_H

#include "ep/handler/eventHandler.h"
#include "store/database.h"

namespace RS::ep {
/**
 * database의 비동기 작업이 끝났다는 신호(eventfd)를 받아 reap()으로 결과를 회수한다.
 * fd는 database가 소유하므로 여기서 닫지 않는다.
 */
class storeHandler : public eventHandler {
private:
    store::database& db_;
public:
    explicit storeHandler(store::database& db);	// db.start_worker() 뒤에 만들어야 한다 (done_fd가 그때 생김)
    int fd() const override;	// database::done_fd()
    eventHandlerResult on_readable() noexcept override;	// eventfd 카운터를 읽어 비우고 reap()
};
}

#endif
