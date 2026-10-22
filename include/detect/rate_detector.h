#ifndef RATE_DETECTOR_H
#define RATE_DETECTOR_H

#include <cstdint>
#include <deque>
#include <unordered_map>

#include "detect/config.h"

namespace RS::detect {

/**
 * 출발지 IP별로 최근 window 안의 요청 시각을 슬라이딩 윈도우로 보관하고,
 * 개수가 threshold 이상이면 on_exceed를 돌려준다.
 */
class rate_detector {
private:
    detector_config config_;
    std::unordered_map<uint32_t, std::deque<time_point>> history_;
    void drop_timeout(std::deque<time_point>& target, time_point now);
    void resize_once(std::deque<time_point>& target);
public:
    explicit rate_detector(const detector_config& con);
    verdict feed(uint32_t ip, time_point now);
};

}

#endif
