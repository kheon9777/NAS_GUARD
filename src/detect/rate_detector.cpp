#include "detect/rate_detector.h"

#include <iterator>

namespace RS::detect {
rate_detector::rate_detector(const detector_config& con) : config_(con) {
}
verdict rate_detector::feed(uint32_t ip, time_point now) {
    auto& target = history_[ip];
    target.push_back(now);
    drop_timeout(target, now);
    resize_once(target);
    return target.size() >= config_.threshold ? config_.on_exceed : verdict::ok;
}
// 타이머에서 주기적으로 호출. feed()가 안 불리는 IP는 여기서만 정리된다
void rate_detector::expire(time_point now) {
    for(auto iter = history_.begin(); iter != history_.end();) {
        drop_timeout(iter->second, now);
        iter = iter->second.empty() ? history_.erase(iter) : std::next(iter);
    }
}
// 창 밖으로 나간 오래된 이벤트를 앞에서부터 제거
void rate_detector::drop_timeout(std::deque<time_point>& target, time_point now) {
    while(!target.empty() && now - target.front() > config_.window) {
        target.pop_front();
    }
}
// 상한 초과분 제거 (호출당 1개씩 들어오므로 초과분은 항상 1개)
void rate_detector::resize_once(std::deque<time_point>& target) {
    if(target.size() > config_.horizen) {
        target.pop_front();
    }
}
}
