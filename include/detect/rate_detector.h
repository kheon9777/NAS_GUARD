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
    void drop_timeout(std::deque<time_point>& target, time_point now);	// window 밖으로 나간 오래된 시각을 앞에서 제거
    void resize_once(std::deque<time_point>& target);	// horizen 초과분 제거 (호출당 1개 들어오므로 1개만)
public:
    explicit rate_detector(const detector_config& con);
    void reconfigure(const detector_config& con) { config_ = con; }	// 기록은 유지하고 임계치만 교체 (리로드)
    verdict feed(uint32_t ip, time_point now);	// 이벤트 하나 기록. 창 안 개수가 threshold 이상이면 on_exceed
    void expire(time_point now);	// 창 안에 이벤트가 하나도 없는 IP를 삭제
    size_t tracked() const { return history_.size(); }	// 추적 중인 IP 수 (메모리 로그용)
};

}

#endif
