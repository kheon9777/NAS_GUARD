#include "block/block_ip.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>

#include "util/logger.h"

namespace RS::block {

// fork + exec nft. 반환: 자식 pid, fork 실패 -1. 기다리지 않는다
static pid_t spawn_nft(const char* const argv[]) {
    util::log_flush();	// fork 전에 비워서 자식이 부모의 버퍼를 복사해 두 번 찍는 일을 막음
    pid_t pid = fork();
    if(pid < 0) {
        util::error("spawn_nft > fork: ", std::strerror(errno));
        return -1;
    }
    if(pid == 0) {
        // 자식 프로세스: nft로 변신
        execvp("nft", const_cast<char* const*>(argv));
// error ---------------------------------------------------------------------
        util::error("spawn_nft > execvp: ", std::strerror(errno));	// 여기 왔다면 실행 실패
        util::log_flush();	// _exit는 버퍼를 안 비우므로 직접 비움
        _exit(127);
// ---------------------------------------------------------------------------
    }
    return pid;
}

// nft 스크립트 한 덩어리를 실행하고 끝날 때까지 기다린다. 반환: exit code, fork/wait 실패 -1
static int run_nft_sync(const char* script) {
    const char* argv[] = {"nft", script, nullptr};
    pid_t pid = spawn_nft(argv);
    if(pid < 0) return -1;

    int status = 0;
    if(waitpid(pid, &status, 0) < 0) {
        util::error("run_nft_sync > waitpid: ", std::strerror(errno));
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

pid_t block_ip(uint32_t ip, int timeout_sec, const nft_names& n) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));

    char element[64];
    std::snprintf(element, sizeof(element), "{ %s timeout %ds }", ip_str, timeout_sec);

    const char* argv[] = {"nft", "add", "element", n.family.c_str(), n.table.c_str(), n.set.c_str(), element, nullptr};
    // 부모 프로세스: 기다리지 않고 pid만 돌려줌. 종료는 SIGCHLD로 통지받아 blocker::reap()이 회수
    return spawn_nft(argv);
}

bool nft_setup(const nft_names& n) {
    // 재시작해도 차단이 유지되도록 테이블과 set은 있으면 그대로 둔다 (add는 이미 있어도 실패하지 않음).
    // 규칙만 중복되지 않게 체인을 flush하고 다시 넣는다. set 원소는 체인과 별개라 flush에 영향 없음.
    // blocklist에 든 IP는 모든 포트를 drop. 22번 예외는 두지 않는다 (내 IP는 whitelist가 지킴)
    char script[512];
    std::snprintf(script, sizeof(script),
        "add table %s %s; "
        "add set %s %s %s { type ipv4_addr; flags timeout; }; "
        "add chain %s %s %s { type filter hook input priority %d; policy accept; }; "
        "flush chain %s %s %s; "
        "add rule %s %s %s ip saddr @%s drop",
        n.family.c_str(), n.table.c_str(),
        n.family.c_str(), n.table.c_str(), n.set.c_str(),
        n.family.c_str(), n.table.c_str(), n.chain.c_str(), n.priority,
        n.family.c_str(), n.table.c_str(), n.chain.c_str(),
        n.family.c_str(), n.table.c_str(), n.chain.c_str(), n.set.c_str());
    int rc = run_nft_sync(script);
    if(rc != 0) {
        util::error("nft_setup > nft failed (exit=", rc, ")");
        return false;
    }
    util::info("[nft] table ", n.family, " ", n.table, " ready");
    return true;
}

bool nft_teardown(const nft_names& n) {
    char script[128];
    std::snprintf(script, sizeof(script), "delete table %s %s", n.family.c_str(), n.table.c_str());
    int rc = run_nft_sync(script);
    if(rc != 0) {
        util::error("nft_teardown > nft failed (exit=", rc, ")");
        return false;
    }
    util::info("[nft] table ", n.family, " ", n.table, " removed");
    return true;
}

}
