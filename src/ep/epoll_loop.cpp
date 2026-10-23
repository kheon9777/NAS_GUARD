#include "ep/epoll_loop.h"

#include <cstdlib>
#include <memory>
#include <system_error>

#include "block/blocker.h"
#include "block/whitelist.h"
#include "detect/analyzer.h"
#include "detect/device_tracker.h"
#include "ep/epoll_RS.h"
#include "ep/handler/rawsockHandler.h"
#include "ep/handler/signalHandler.h"
#include "ep/handler/storeHandler.h"
#include "ep/handler/timerHandler.h"
#include "ep/reloader.h"
#include "settings.h"
#include "store/block_store.h"
#include "store/database.h"
#include "store/device_store.h"
#include "store/settings_store.h"
#include "store/whitelist_store.h"
#include "util/logger.h"

namespace RS::ep {
static bool g_working = true;

int do_loop() {
    int rc = 0;
    util::set_log_level_from_env();	// GUARD_LOG_LEVEL=debug 로 낮출 수 있음
    try {
        // 설정: DB tbl_config_info 한 행. 로그 파일 경로도 여기서 오므로 파일 로그는 그 뒤에 연다 (그전 로그는 stdout만)
        const char* db_path = std::getenv("GUARD_DB_PATH");
        if(db_path == nullptr) db_path = settings::DB_PATH;
        store::database db;
        if(!db.open(db_path)) return 1;
        settings cfg;
        if(!store::load_settings(db, cfg)) return 1;

        util::set_log_keep_days(cfg.log_keep_days);	// log_open이 여는 김에 오래된 파일도 지우므로 그 전에
        if(!util::log_open(cfg.log_path.c_str())) {
            util::warn("log file open failed: ", cfg.log_path, " (stdout only)");
        }
        util::info("guard starting (log level ", util::log_level_name(util::get_log_level()), ", db ", db_path, ")");
        util::info("[settings] ", cfg.summary());

        // 패킷 식별기
        detect::analyzer analyzer_obj{detect::config{cfg}};

        // 장비 목록 (ARP). DB에 있던 장비를 복원해서 재시작 때 전부 "새 장비"로 뜨지 않게 한다
        detect::device_tracker devices_obj{make_device_config(cfg)};
        if(!store::load_devices(db, devices_obj)) return 1;
        if(!store::ensure_block_table(db)) return 1;	// 차단 기록 테이블

        // 블로커
        block::blocker blocker_obj{cfg.block_timeout,
            block::nft_names{cfg.nft_family, cfg.nft_table, cfg.nft_set, cfg.nft_chain, cfg.nft_priority}};
        if(!blocker_obj.setup_nft()) {	// 테이블, set, 규칙 생성. 실패하면 차단이 안 되므로 시작하지 않음
            return 1;
        }

        // 화이트리스트: whitelist.local.h 항목 + tbl_whitelist 행. 잘못된 항목이 있으면 시작하지 않는다 (내 IP가 빠지면 접속이 끊김)
        block::whitelist whitelist_obj;
        if(!store::load_whitelist(db, whitelist_obj)) return 1;

        epoll_RS epoll_obj{cfg.loop_timeout_ms};
        epoll_obj.add(std::make_unique<rawsockHandler>(analyzer_obj, whitelist_obj, blocker_obj, devices_obj, db));
        auto& timer_obj = static_cast<timerHandler&>(epoll_obj.add(
            std::make_unique<timerHandler>(cfg.expire_interval, cfg.mem_log_every_ticks, blocker_obj, analyzer_obj, devices_obj, db)));

        // SIGHUP 리로드. 적용 대상이 다 만들어진 뒤에 묶는다
        reloader reloader_obj{db, cfg, analyzer_obj, devices_obj, blocker_obj, whitelist_obj, epoll_obj, timer_obj};
        epoll_obj.add(std::make_unique<signalHandler>(blocker_obj, reloader_obj));	// 여기서 시그널을 막는다. 스레드는 이 뒤에 만든다

        // DB 비동기 워커. 시그널 마스크를 물려받도록 signalHandler 다음에 시작한다
        if(!db.start_worker()) return 1;
        epoll_obj.add(std::make_unique<storeHandler>(db));

        RS::util::info("=========== loop start ===========");
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
            case epoll_RS::result::error : {	// 치명적 (epoll_wait 실패 또는 핸들러 복구 불가). 원인은 각자 로그 남김
                RS::util::error("fatal error in event loop, exiting");
                g_working = false;
                rc = 1;
                break;
            }
            default:
                break;
            }
        }
        RS::util::info("=========== end loop ===========");
    } catch (const std::system_error& e) {	// 초기화 실패
        RS::util::error(e.what());
        rc = 1;
    }
    return rc;
}

void set_g_working(bool val) {
    g_working = val;
}

}
