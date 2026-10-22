#include "ep/epoll_loop.h"

#include <chrono>
#include <memory>
#include <system_error>

#include "block/blocker.h"
#include "block/whitelist.h"
#include "detect/analyzer.h"
#include "ep/epoll_RS.h"
#include "ep/handler/rawsockHandler.h"
#include "ep/handler/signalHandler.h"
#include "ep/handler/timerHandler.h"
#include "util/logger.h"

namespace RS::ep {
constexpr int LOOP_TIMEOUT = 1000;
constexpr std::chrono::seconds EXPIRE_INTERVAL{1};      // 만료 정리 주기
static bool g_working = true;

int do_loop() {
    int rc = 0;
    try {
        // 패킷 식별기
        detect::config analyzer_config {
            .tcp_rate{.window = std::chrono::seconds{3}, .threshold = 15, .horizen=500, .on_exceed=detect::verdict::tcp_syn_flood},
        };
        detect::analyzer analyzer_obj{analyzer_config};

        // 블로커
        block::blocker blocker_obj{std::chrono::seconds(10)};

        // 화이트리스트
        block::whitelist whitelist_obj;
        whitelist_obj.add("127.0.0.0", "255.0.0.0"); // 루프백
        whitelist_obj.add("172.30.1.0", "255.255.255.0"); // 스위트마이홈
        whitelist_obj.add("58.72.0.242"); // 외부1

        epoll_RS epoll_obj{LOOP_TIMEOUT};
        epoll_obj.add(std::make_unique<signalHandler>(blocker_obj));
        epoll_obj.add(std::make_unique<rawsockHandler>(analyzer_obj, whitelist_obj, blocker_obj));
        epoll_obj.add(std::make_unique<timerHandler>(EXPIRE_INTERVAL, blocker_obj, analyzer_obj));

        RS::util::logger("=========== loop start ===========");
        while(g_working) {
            epoll_RS::result wait_res = epoll_obj.wait();
            switch(wait_res) {
            case epoll_RS::result::timeout : {
                //timeout
                break;
            }
            case epoll_RS::result::has_event : {
                // has event
                break;
            }
            case epoll_RS::result::error : {       // 치명적 (epoll_wait 실패 또는 핸들러 복구 불가). 원인은 각자 로그 남김
                RS::util::logger("fatal error in event loop, exiting");
                g_working = false;
                rc = 1;
                break;
            }
            default:
                break;
            }
        }
        RS::util::logger("=========== end loop ===========");
    } catch (const std::system_error& e) {         // 초기화 실패
        RS::util::logger(e.what());
        rc = 1;
    }
    return rc;
}

void set_g_working(bool val) {
    g_working = val;
}

}
