#ifndef RELOADER_H
#define RELOADER_H

#include "block/blocker.h"
#include "block/whitelist.h"
#include "detect/analyzer.h"
#include "detect/device_tracker.h"
#include "ep/epoll_RS.h"
#include "ep/handler/timerHandler.h"
#include "settings.h"
#include "store/database.h"

namespace RS::ep {

// settings의 장비 감지 항목을 device_config로 옮긴다. 시작과 리로드가 같이 쓴다
detect::device_config make_device_config(const settings& s);

/**
 * SIGHUP 리로드. 설정(tbl_config_info)과 화이트리스트(whitelist.local.h + tbl_whitelist)를 DB에서 다시 읽어
 * 돌고 있는 객체에 적용한다. 각 단계는 읽기에 실패하면 기존 값을 유지한다.
 * 적용: 임계치(analyzer), 장비 설정(device_tracker), 차단 시간(blocker), epoll 타임아웃, 타이머 주기와 메모리 로그 주기.
 * 미적용: nft_*와 log_path (테이블, 파일을 다시 만들어야 하므로 재시작 필요. 바뀌었으면 warn).
 * 장비 목록(tbl_device)은 guard가 쓰는 쪽이라 다시 읽지 않는다.
 * 루프 경로에서 signalHandler가 부르므로 던지지 않는다.
 */
class reloader {
private:
    store::database& db_;
    settings& cfg_;	// 현재 적용된 값. 리로드 성공 시 갱신
    detect::analyzer& anyz_;
    detect::device_tracker& devices_;
    block::blocker& blocker_;
    block::whitelist& wlist_;
    epoll_RS& ep_;
    timerHandler& timer_;
    void reload_settings() noexcept;	// tbl_config_info를 다시 읽어 각 객체에 적용. 실패하면 기존 값 유지
    void reload_whitelist() noexcept;	// 새 목록을 따로 채운 뒤 전부 성공했을 때만 교체
public:
    reloader(store::database& db, settings& cfg, detect::analyzer& anyz, detect::device_tracker& devices,
        block::blocker& blocker, block::whitelist& wlist, epoll_RS& ep, timerHandler& timer);	// 적용 대상들을 참조로 묶는다. 전부 먼저 만들어져 있어야 함
    void reload() noexcept;	// SIGHUP 때 signalHandler가 호출. 설정 -> 화이트리스트 순
};

}

#endif
