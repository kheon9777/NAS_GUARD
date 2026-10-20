#include <sys/wait.h>
#include <unistd.h>
#include <cstdio>

bool block_ip(const char* ip, int timeout_sec) {
    char element[64];
    std::snprintf(element, sizeof(element), "{ %s timeout %ds }", ip, timeout_sec);

    pid_t pid = fork();
    if (pid < 0) {
        std::perror("fork");
        return false;
    }

    if (pid == 0) {
        // 자식 프로세스: nft로 변신
        const char* argv[] = {"nft", "add", "element", "inet", "guard", "blocklist", element, nullptr};
        execvp("nft", const_cast<char* const*>(argv));
// error ---------------------------------------------------------------------
        std::perror("execvp");      // 여기 왔다면 실행 실패
        _exit(127);
// ---------------------------------------------------------------------------
    }

    // 부모 프로세스: 자식이 끝날 때까지 기다림
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        std::perror("waitpid");
        return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}