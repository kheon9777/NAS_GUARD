#include "block/blocker.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <iterator>

#include "block/block_ip.h"
#include "util/logger.h"

namespace RS::block {
blocker::blocker(std::chrono::seconds timeout) : timeout_(timeout) {
}
void blocker::block(uint32_t ip, time_point now) {
    ips_[ip] = now + timeout_; // nft 결과와 무관하게 메모리에는 먼저 기록 (재감지 폭주 방지)
    pid_t pid = block_ip(ip, static_cast<int>(timeout_.count()));
    if(pid > 0) {
        pending_[pid] = ip;
    }
}
bool blocker::is_blocked(uint32_t ip, time_point now) const {
    auto iter = ips_.find(ip);
    return iter != ips_.end() && iter->second > now;
}
// 만료된 항목 정리. 타이머에서 주기적으로 호출. nft 쪽은 set timeout이 알아서 지움
void blocker::expire(time_point now) {
    for(auto iter = ips_.begin(); iter != ips_.end();) {
        iter = (now >= iter->second) ? ips_.erase(iter) : std::next(iter);
    }
}
// SIGCHLD는 여러 자식이 동시에 끝나도 한 번만 올 수 있으므로, 끝난 자식이 없을 때까지 돈다
void blocker::reap() {
    int status = 0;
    pid_t pid;
    while((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        auto iter = pending_.find(pid);
        if(iter == pending_.end()) continue;
        bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        char ip_buf[INET_ADDRSTRLEN];           // std::string 할당 없이 스택 버퍼로
        inet_ntop(AF_INET, &iter->second, ip_buf, sizeof(ip_buf));
        if(ok) {
            // 성공시
            util::logger("[blocked] nft ok: ", ip_buf);
        } else {
            // 실패시
            util::logger("[block failed] nft FAILED (exit=", WEXITSTATUS(status), "): ", ip_buf);
        }
        pending_.erase(iter);
    }
}
}
