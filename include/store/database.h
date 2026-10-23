#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <variant>
#include <vector>

namespace RS::store {

using param = std::variant<int64_t, std::string>;	// SQL의 ? 자리에 바인딩할 값

// SELECT 결과 한 행. query()의 콜백 안에서만 유효하다
class row {
private:
    sqlite3_stmt* stmt_;
public:
    explicit row(sqlite3_stmt* stmt) : stmt_(stmt) {}
    int64_t integer(int col) const;	// INTEGER 컬럼. col은 0부터
    std::string text(int col) const;	// NULL이면 빈 문자열
    bool is_null(int col) const;	// NULL 여부 (text()는 NULL을 빈 문자열로 주므로 구분이 필요하면 이걸로)
};

/**
 * SQLite 연결 하나. 동기와 비동기 두 가지로 쓴다.
 *  - 동기 exec() / query(): 끝날 때까지 기다린다. 초기화 단계(스키마, 설정 읽기)용.
 *  - 비동기 exec_async(): 큐에 넣고 바로 돌아온다. 워커 스레드가 순서대로 실행하고, 하나 끝날 때마다
 *    done_fd()(eventfd)에 신호를 보낸다. storeHandler가 그 fd를 epoll로 받아 reap()을 불러 결과를
 *    로그로 남긴다. 루프 경로(감지, 차단 기록)용. nft의 SIGCHLD -> blocker::reap()과 같은 모양이다.
 * 연결은 FULLMUTEX로 열어서 두 스레드가 같은 핸들을 써도 sqlite 안에서 직렬화된다.
 * 로그는 메인 스레드(reap)에서만 남긴다. logger가 스레드 안전하지 않아 워커는 logger를 부르지 않는다.
 * 실패는 전부 bool로 알리고 던지지 않는다 (루프 경로에서도 쓰이므로).
 */
class database {
private:
    struct job {
        std::string sql;
        std::vector<param> params;
        std::string tag;	// 로그에 찍을 짧은 이름
    };
    struct result {
        bool ok;
        std::string tag;
        std::string err;
    };
    sqlite3* db_ = nullptr;
    int done_fd_ = -1;	// eventfd. 워커가 작업 하나 끝낼 때마다 1 더함
    std::thread worker_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<job> jobs_;
    std::deque<result> results_;
    bool stop_ = false;
    bool run(const std::string& sql, const std::vector<param>& params, std::string& err);	// prepare, bind, step. 두 경로가 같이 씀
    void worker_main();	// 워커 스레드 본문. 시그널을 전부 막고 큐가 비고 stop_일 때까지 돈다
public:
    database() = default;
    ~database();
    database(const database&) = delete;
    database& operator=(const database&) = delete;

    bool open(const char* path);	// 실패하면 로그 남기고 false. 성공하면 WAL, busy_timeout 설정
    void close();	// 워커를 멈추고(큐에 남은 작업은 끝까지 실행) 연결을 닫는다. 소멸자도 부름
    bool is_open() const { return db_ != nullptr; }

    // 동기
    bool exec(const std::string& sql, const std::vector<param>& params = {});	// params가 없으면 여러 문장(;)도 한 번에 실행
    bool query(const std::string& sql, const std::vector<param>& params, const std::function<void(const row&)>& on_row);	// SELECT. 행마다 on_row 호출

    // 비동기
    bool start_worker();	// eventfd를 만들고 워커 스레드를 시작. signalHandler가 시그널을 막은 뒤에 부를 것
    bool exec_async(std::string sql, std::vector<param> params = {}, std::string tag = {});	// 큐에 넣고 즉시 반환. 워커가 없으면 false. tag는 결과 로그용
    int done_fd() const { return done_fd_; }	// eventfd. start_worker() 전에는 -1
    void reap();	// 끝난 작업 결과를 전부 꺼내 로그. storeHandler가 부름
    size_t pending() const;	// 아직 끝나지 않은 비동기 작업 수 (메모리 로그용)
};

}

#endif
