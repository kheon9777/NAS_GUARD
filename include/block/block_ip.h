#ifndef BLOCK_IP_H
#define BLOCK_IP_H

#include <sys/types.h>
#include <cstdint>
#include <string>

namespace RS::block {

// nft 객체 이름. settings(DB)에서 오고 시작 때 한 번 정해진다 (리로드로 바꾸지 않음. 테이블을 다시 만들어야 하므로)
struct nft_names {
    std::string family;	// inet
    std::string table;	// guard
    std::string set;	// blocklist
    std::string chain;	// input
    int priority;	// -10
};

/**
 * nft blocklist set에 IP를 timeout과 함께 추가한다. ip는 네트워크 바이트 순서.
 * 자식 프로세스로 `nft add element inet guard blocklist { ip timeout Ns }`를 실행하고
 * 기다리지 않고 바로 돌아온다. 결과는 SIGCHLD -> blocker::reap()에서 회수한다.
 * 반환: 자식 pid, fork 실패면 -1.
 */
pid_t block_ip(uint32_t ip, int timeout_sec, const nft_names& n);

/**
 * 테이블, set, 체인과 drop 규칙을 만든다.
 * 테이블과 set이 이미 있으면 그대로 둬서 재시작 전의 차단이 유지된다. 규칙은 체인을 flush하고 다시 넣어 중복을 막는다.
 * 초기화 단계용이라 동기로 기다린다.
 */
bool nft_setup(const nft_names& n);

/**
 * 테이블을 통째로 지운다 (차단 전부 해제). 종료 시 자동으로 부르지 않는다.
 * 완전히 걷어낼 때 명시적으로 쓰는 용도. 동기.
 */
bool nft_teardown(const nft_names& n);

}

#endif
