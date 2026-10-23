#ifndef DETECT_CONFIG_H
#define DETECT_CONFIG_H

#include <chrono>
#include <cstddef>
#include <cstdint>

#include "settings.h"

namespace RS::detect {

using time_point = std::chrono::steady_clock::time_point;

// analyze() 결과. ok 외는 차단 사유
enum class verdict {
    ok, port_scan, tcp_syn_flood, icmp_flood
};

// 로그와 DB(tbl_block.reason)에 쓰는 이름
constexpr const char* verdict_name(verdict v) {
    switch(v) {
    case verdict::port_scan: return "port_scan";
    case verdict::tcp_syn_flood: return "tcp_syn_flood";
    case verdict::icmp_flood: return "icmp_flood";
    default: return "ok";
    }
}

// 감지기 하나의 설정. window 안에 threshold개 이상이면 on_exceed를 돌려준다. horizen은 IP당 기록 상한
struct detector_config {
    std::chrono::seconds window{3};
    uint32_t threshold = 15;
    size_t horizen = 500;
    verdict on_exceed = verdict::ok;
};

// 감지기별 설정. 값은 settings(DB)에서 온다
struct config {
    detector_config scan;
    detector_config tcp_rate;
    detector_config icmp_rate;
    explicit config(const RS::settings& s) :
        scan{s.scan_window, s.scan_threshold, s.max_horizen, verdict::port_scan},
        tcp_rate{s.tcp_rate_window, s.tcp_rate_threshold, s.max_horizen, verdict::tcp_syn_flood},
        icmp_rate{s.icmp_rate_window, s.icmp_rate_threshold, s.max_horizen, verdict::icmp_flood} {
    }
};

}

#endif
