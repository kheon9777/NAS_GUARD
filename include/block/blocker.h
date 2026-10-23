#ifndef BLOCKER_H
#define BLOCKER_H

#include <sys/types.h>
#include <chrono>
#include <cstdint>
#include <unordered_map>

#include "block/block_ip.h"

namespace RS::block {

using time_point = std::chrono::steady_clock::time_point;

/**
 * 차단 IP 목록. 메모리에 <IP,만료 시각>을 들고 있다가 만료되면 expire()에서 지운다.
 * 메모리 만료 시간은 nft set의 timeout과 같아야 한다 (메모리가 늦게 풀리면 그동안 감지를 건너뜀).
 *
 * nft 명령은 자식 프로세스로 실행하고 기다리지 않는다. 자식이 끝나면 SIGCHLD가 오고,
 * signalHandler가 reap()을 불러 결과를 회수한다. 그래서 이벤트 루프가 nft 때문에 멈추지 않는다.
 *
 * nft 테이블은 setup_nft()에서 만들고, 종료할 때 지우지 않는다. 재시작 사이에도 차단이 유지되고
 * guard가 꺼져 있는 동안에도 남은 timeout까지는 커널이 계속 막는다. 메모리 목록(ips_)은 프로세스와 함께
 * 사라지지만, 재감지되면 add element가 기존 원소의 timeout을 갱신하므로 동작에 문제는 없다.
 * 생성자에서 던지지 않고 bool로 알리는 건 초기화 경로도 C 스타일 반환 코드로 맞추기 위해서다.
 */
class blocker {
private:
    std::chrono::seconds timeout_;
    nft_names names_;
    std::unordered_map<uint32_t, time_point> ips_;	// 차단 중인 IP -> 만료 시각
    std::unordered_map<pid_t, uint32_t> pending_;	// 결과를 아직 못 받은 nft 자식 -> 대상 IP
public:
    blocker(std::chrono::seconds timeout, const nft_names& names);	// timeout: 차단 유지 시간 (nft set timeout과 메모리 만료에 같이 씀)
    void set_timeout(std::chrono::seconds timeout) { timeout_ = timeout; }	// 리로드. 이미 차단 중인 것은 그대로
    bool setup_nft();	// 초기화 단계에서 한 번. 실패하면 false (원인은 로그)
    void block(uint32_t ip, time_point now);	// 메모리에 기록하고 nft add element를 비동기로 실행. 이미 차단 중이면 만료만 연장
    bool is_blocked(uint32_t ip, time_point now) const;	// 차단 중이고 아직 만료 전이면 true
    void expire(time_point now);	// 만료된 항목을 메모리에서 제거. 타이머가 주기적으로 호출 (nft 쪽은 커널이 알아서 지움)
    void reap();	// SIGCHLD 때 호출. 끝난 nft 자식들을 전부 회수
    size_t blocked() const { return ips_.size(); }	// 차단 중인 IP 수 (메모리 로그용)
    size_t pending() const { return pending_.size(); }	// 결과 대기 중인 nft 자식 수
};

}

#endif
