#include "ep/epoll_loop.h"

#include <system_error>

#include "util/logger.h"
#include "ep/epoll_RS.h"
#include "ep/handler/signalHandler.h"
#include "ep/handler/rawsockHandler.h"

namespace RS::ep {
constexpr int LOOP_TIMEOUT = 1000;
static bool g_working = true;

void do_loop() {
    try {
        epoll_RS epoll_obj{LOOP_TIMEOUT};
        epoll_obj.add(std::make_unique<signalHandler>());
        epoll_obj.add(std::make_unique<rawsockHandler>());

        RS::util::logger("=========== loop start ===========");
        while(g_working) {
            epoll_RS::result wait_res = epoll_obj.wait();
            switch (wait_res) {
            case epoll_RS::result::timeout : {
                //timeout
                RS::util::logger("<<timeout>>");
                break;
            }
            case epoll_RS::result::has_event : {
                // has event
                break;
            }
            default:
                break;
            }
        }
        RS::util::logger("=========== end loop ===========");
    } catch (const std::system_error& e) {
        RS::util::logger(e.what());
    }
}

void set_g_working(bool val) {
    g_working = val;
}

}