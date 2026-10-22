#ifndef BLOCKER_H
#define BLOCKER_H

#include <sys/types.h>
#include <chrono>
#include <cstdint>
#include <unordered_map>

namespace RS::block {

using time_point = std::chrono::steady_clock::time_point;

/**
 * 차단 IP 목록. 메모리에 <IP,만료 시각>을 들고 있다가 만료되면 expire()에서 지운다.
 * 메모리 만료 시간은 nft set의 timeout과 같아야 한다 (메모리가 늦게 풀리면 그동안 감지를 건너뜀).
 *
 * nft 명령은 자식 프로세스로 실행하고 기다리지 않는다. 자식이 끝나면 SIGCHLD가 오고,
 * signalHandler가 reap()을 불러 결과를 회수한다. 그래서 이벤트 루프가 nft 때문에 멈추지 않는다.
 */
class blocker {
private:
    std::chrono::seconds timeout_;
    std::unordered_map<uint32_t, time_point> ips_;      // 차단 중인 IP -> 만료 시각
    std::unordered_map<pid_t, uint32_t> pending_;       // 결과를 아직 못 받은 nft 자식 -> 대상 IP
public:
    explicit blocker(std::chrono::seconds timeout);
    void block(uint32_t ip, time_point now);
    bool is_blocked(uint32_t ip, time_point now) const;
    void expire(time_point now);
    void reap();                                        // SIGCHLD 때 호출. 끝난 nft 자식들을 전부 회수
};

}

#endif
