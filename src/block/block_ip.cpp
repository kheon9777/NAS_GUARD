#include "block/block_ip.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>

#include "util/logger.h"

namespace RS::block {
pid_t block_ip(uint32_t ip, int timeout_sec) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));

    char element[64];
    std::snprintf(element, sizeof(element), "{ %s timeout %ds }", ip_str, timeout_sec);

    std::cout.flush();      // fork 전에 비워서 자식이 부모의 버퍼를 복사해 두 번 찍는 일을 막음
    pid_t pid = fork();
    if(pid < 0) {
        util::logger("block_ip > fork: ", std::strerror(errno));
        return -1;
    }

    if(pid == 0) {
        // 자식 프로세스: nft로 변신
        const char* argv[] = {"nft", "add", "element", "inet", "guard", "blocklist", element, nullptr};
        execvp("nft", const_cast<char* const*>(argv));
// error ---------------------------------------------------------------------
        util::logger("block_ip > execvp: ", std::strerror(errno));      // 여기 왔다면 실행 실패
        std::cout.flush();      // _exit는 버퍼를 안 비우므로 직접 비움
        _exit(127);
// ---------------------------------------------------------------------------
    }

    // 부모 프로세스: 기다리지 않고 pid만 돌려줌. 종료는 SIGCHLD로 통지받아 blocker::reap()이 회수
    return pid;
}
}
