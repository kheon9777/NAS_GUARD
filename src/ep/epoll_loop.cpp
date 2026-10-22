#include "ep/epoll_loop.h"

#include <chrono>
#include <memory>
#include <system_error>

#include "detect/analyzer.h"
#include "block/whitelist.h"
#include "ep/epoll_RS.h"
#include "ep/handler/rawsockHandler.h"
#include "ep/handler/signalHandler.h"
#include "util/logger.h"

namespace RS::ep {
constexpr int LOOP_TIMEOUT = 1000;
static bool g_working = true;

void do_loop() {
    try {
        // 패킷 식별기
        detect::config analyzer_config {
            .tcp_rate{.window = std::chrono::seconds{3}, .threshold = 15, .horizen=500, .on_exceed=detect::verdict::tcp_syn_flood},
        };
        detect::analyzer analyzer_obj{analyzer_config};

        // 화이트리스트
        block::whitelist whitelist_obj;
        whitelist_obj.add("127.0.0.1");
        whitelist_obj.add("160.79.104.10");

        epoll_RS epoll_obj{LOOP_TIMEOUT};
        epoll_obj.add(std::make_unique<signalHandler>());
        epoll_obj.add(std::make_unique<rawsockHandler>(analyzer_obj, whitelist_obj));

        RS::util::logger("=========== loop start ===========");
        while(g_working) {
            epoll_RS::result wait_res = epoll_obj.wait();
            switch(wait_res) {
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
