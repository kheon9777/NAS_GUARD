#ifndef ANALYZER_H
#define ANALYZER_H

#include "detect/config.h"
#include "detect/rate_detector.h"
#include "packet/ip_RS.h"

namespace RS::detect {

/**
 * 감지기들을 소유하고, 패킷 종류에 따라 맞는 감지기에 넘겨 판정 결과를 돌려준다.
 */
class analyzer {
private:
    rate_detector rate_tcp_;	// ACK 없는 TCP
    rate_detector rate_icmp_;	// ICMP echo request
public:
    explicit analyzer(const config& con);	// 감지기별 설정으로 rate_detector들을 만든다
    void reconfigure(const config& con);	// 리로드. 추적 기록은 유지
    verdict analyze(const packet::ip_RS& ip);	// 셀 패킷(TCP no-ACK, ICMP echo request)만 감지기에 넘김. 나머지는 ok
    void expire(time_point now);	// 모든 감지기의 expire() 호출
    size_t tracked() const;	// 모든 감지기가 추적 중인 IP 수 합계
};

}

#endif
