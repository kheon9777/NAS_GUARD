#ifndef SETTINGS_H
#define SETTINGS_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

namespace RS {

/**
 * 운영 설정값. 기본값은 여기 멤버 초기화에 있고, 시작 때 store::load_settings()가
 * DB의 tbl_config_info 한 행(id = 1)을 읽어 덮어쓴다. 행이 없으면 이 기본값으로 한 행을 넣는다.
 * 루프가 돌기 전에 한 번 채우고, 이후에는 각 객체가 생성자로 받은 값만 쓴다 (루프 중에 바뀌지 않음).
 * 값을 바꾸려면 DB 행을 UPDATE 하고 재시작한다. 화이트리스트 항목은 개인 데이터라 block/whitelist.local.h에 따로 둔다.
 */
struct settings {
    // ---- 컴파일 시점 상수 (배열 크기, DB를 열기 전에 필요한 값) ----
    static constexpr int MAX_EVENTS = 20;	// epoll_wait 한 번에 받는 이벤트 수
    static constexpr const char* DB_PATH = "guard.db";	// 환경변수 GUARD_DB_PATH가 있으면 그것을 쓴다

    // ---- 감지 임계치 (window 안에 threshold 개 이상이면 판정) ----
    // 지금 기본값은 LAN에서 손으로 테스트하기 위한 낮은 값. 운영 때는 DB에서 올린다
    std::chrono::seconds scan_window{3};	// 포트 스캔: N초 안에
    uint32_t scan_threshold = 15;	//            서로 다른 포트 N개 이상
    std::chrono::seconds tcp_rate_window{3};	// TCP 연속 요청: N초 안에
    uint32_t tcp_rate_threshold = 15;	//                ACK 없는 패킷 N개 이상
    std::chrono::seconds icmp_rate_window{10};	// ICMP 플러드: N초 안에
    uint32_t icmp_rate_threshold = 100;	//              echo request N개 이상
    size_t max_horizen = 500;	// IP당 보관하는 이벤트 상한 (메모리 상한)

    // ---- 차단 ----
    std::chrono::seconds block_timeout{10};	// 차단 유지 시간. nft set timeout과 메모리 만료에 같이 쓰임
    std::string nft_family = "inet";
    std::string nft_table = "guard";
    std::string nft_set = "blocklist";
    std::string nft_chain = "input";
    int nft_priority = -10;	// filter(0)보다 먼저 보도록 음수

    // ---- 장비 감지 (ARP) ----
    std::chrono::seconds device_expire{0};	// 이 시간 동안 안 보이면 장비 목록에서 삭제. 0이면 지우지 않음 (기본)
    std::chrono::seconds arp_spoof_window{60};	// 같은 IP의 MAC이 이 시간 안에
    uint32_t arp_spoof_threshold = 3;	// 이 횟수 이상 바뀌면 ARP 스푸핑 의심 (알람)

    // ---- 이벤트 루프 ----
    int loop_timeout_ms = 1000;	// epoll_wait 최대 대기. 0보다 커야 함
    std::chrono::seconds expire_interval{1};	// 만료 정리 타이머 주기
    unsigned long mem_log_every_ticks = 60;	// 메모리 로그 주기 (틱 수). 틱이 1초면 1분

    // ---- 로그 ----
    std::string log_path = "logs/guard.log";	// 상대 경로는 실행 디렉터리 기준. systemd에서는 절대 경로 권장.
                                           	// 실제 파일은 날짜가 붙은 이름 (logs/guard.2026-10-23.log). 날이 바뀌면 새 파일
    int log_keep_days = 7;	// 날짜별 로그 파일 보관 일수. 오늘 기준 이보다 오래된 파일은 지운다. 0이면 지우지 않음

    std::string summary() const;	// 로그용 한 줄 요약 (임계치, 차단 시간, LAN, 장비 설정)
};

}

#endif
