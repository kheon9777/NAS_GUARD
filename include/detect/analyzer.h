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
    rate_detector rate_tcp_;
public:
    explicit analyzer(const config& con);
    verdict analyze(const packet::ip_RS& ip);
};

}

#endif
