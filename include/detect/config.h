#ifndef DETECT_CONFIG_H
#define DETECT_CONFIG_H

#include <chrono>
#include <cstddef>
#include <cstdint>

// 기본 임계치 (초 단위 창, 창 안 허용 횟수)
#define SCAN_WINDOW_S        3      // 포트 스캔: N초 안에
#define SCAN_THRESHOLD       15     //            서로 다른 포트 N개 이상

#define TCP_RATE_WINDOW_S    30     // TCP 연속 요청: N초 안에
#define TCP_RATE_THRESHOLD   50     //                ACK 없는 패킷 N개 이상

#define ICMP_RATE_WINDOW_S   10     // ICMP 플러드: N초 안에
#define ICMP_RATE_THRESHOLD  100    //              echo request N개 이상

#define MAX_HORIZEN 500             // IP당 이벤트 상한

namespace RS::detect {

using time_point = std::chrono::steady_clock::time_point;

enum class verdict {
    ok, port_scan, tcp_syn_flood, icmp_flood
};

struct detector_config {
    std::chrono::seconds window{SCAN_WINDOW_S};
    uint32_t threshold{SCAN_THRESHOLD};
    size_t horizen{MAX_HORIZEN};
    verdict on_exceed{verdict::ok};
};

struct config {
    detector_config scan {
        .window = std::chrono::seconds{SCAN_WINDOW_S}, .threshold = SCAN_THRESHOLD, .horizen = MAX_HORIZEN, .on_exceed = verdict::port_scan};
    detector_config tcp_rate {
        .window = std::chrono::seconds{TCP_RATE_WINDOW_S}, .threshold = TCP_RATE_THRESHOLD, .horizen = MAX_HORIZEN, .on_exceed = verdict::tcp_syn_flood};
    detector_config icmp_rate {
        .window = std::chrono::seconds{ICMP_RATE_WINDOW_S}, .threshold = ICMP_RATE_THRESHOLD, .horizen = MAX_HORIZEN, .on_exceed = verdict::icmp_flood};
};

}

#endif
