#ifndef BLOCK_IP_H
#define BLOCK_IP_H

#include <sys/types.h>
#include <cstdint>

namespace RS::block {

/**
 * nft blocklist set에 IP를 timeout과 함께 추가한다. ip는 네트워크 바이트 순서.
 * 자식 프로세스로 `nft add element inet guard blocklist { ip timeout Ns }`를 실행하고
 * 기다리지 않고 바로 돌아온다. 결과는 SIGCHLD -> blocker::reap()에서 회수한다.
 * 반환: 자식 pid, fork 실패면 -1. 테이블, set은 미리 만들어져 있어야 한다 (expr/06_netfilter/setup.sh 참고).
 */
pid_t block_ip(uint32_t ip, int timeout_sec);

}

#endif
