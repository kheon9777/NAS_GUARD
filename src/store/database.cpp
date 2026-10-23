#include "store/database.h"

#include <signal.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <utility>

#include "util/logger.h"

namespace RS::store {

int64_t row::integer(int col) const {
    return sqlite3_column_int64(stmt_, col);
}
std::string row::text(int col) const {
    const unsigned char* p = sqlite3_column_text(stmt_, col);
    return p ? reinterpret_cast<const char*>(p) : "";
}
bool row::is_null(int col) const {
    return sqlite3_column_type(stmt_, col) == SQLITE_NULL;
}

database::~database() {
    close();
}

bool database::open(const char* path) {
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    if(sqlite3_open_v2(path, &db_, flags, nullptr) != SQLITE_OK) {
        util::error("database::open > ", path, ": ", db_ ? sqlite3_errmsg(db_) : "out of memory");
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }
    // WAL: 쓰는 중에도 다른 프로세스(웹)가 읽을 수 있음. busy_timeout: 잠겨 있으면 3초까지 기다림
    if(!exec("PRAGMA journal_mode=WAL;") || !exec("PRAGMA busy_timeout=3000;")) {
        close();
        return false;
    }
    util::info("[db] opened ", path);
    return true;
}

void database::close() {
    if(worker_.joinable()) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            stop_ = true;
        }
        cv_.notify_all();
        worker_.join();
    }
    if(done_fd_ >= 0) {
        ::close(done_fd_);
        done_fd_ = -1;
    }
    if(db_ != nullptr) {
        sqlite3_close(db_);
        db_ = nullptr;
        util::info("[db] closed");
    }
}

// 실패하면 err에 원인을 담고 false.
// 바인딩할 값이 없으면 sqlite3_exec로 돌려서 "A; B; C;" 같은 여러 문장도 한 번에 실행된다 (스키마, 트랜잭션).
// 값이 있으면 prepare -> bind -> step(DONE까지) -> finalize. 이때는 문장 하나만 실행된다
bool database::run(const std::string& sql, const std::vector<param>& params, std::string& err) {
    if(params.empty()) {
        char* msg = nullptr;
        if(sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &msg) != SQLITE_OK) {
            err = std::string("exec: ") + (msg ? msg : "unknown");
            sqlite3_free(msg);
            return false;
        }
        return true;
    }
    sqlite3_stmt* stmt = nullptr;
    if(sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        err = std::string("prepare: ") + sqlite3_errmsg(db_);
        return false;
    }
    for(size_t i = 0; i < params.size(); i++) {
        int idx = static_cast<int>(i) + 1;	// ? 번호는 1부터
        if(const int64_t* v = std::get_if<int64_t>(&params[i])) {
            sqlite3_bind_int64(stmt, idx, *v);
        } else {
            sqlite3_bind_text(stmt, idx, std::get<std::string>(params[i]).c_str(), -1, SQLITE_TRANSIENT);
        }
    }
    int rc;
    while((rc = sqlite3_step(stmt)) == SQLITE_ROW) {	// 결과 행은 버림 (행이 필요하면 query())
    }
    bool ok = (rc == SQLITE_DONE);
    if(!ok) {
        err = std::string("step: ") + sqlite3_errmsg(db_);
    }
    sqlite3_finalize(stmt);
    return ok;
}

bool database::exec(const std::string& sql, const std::vector<param>& params) {
    std::string err;
    if(!run(sql, params, err)) {
        util::error("database::exec > ", err, " [", sql.substr(0, 60), "]");
        return false;
    }
    return true;
}

bool database::query(const std::string& sql, const std::vector<param>& params,
const std::function<void(const row&)>& on_row) {
    sqlite3_stmt* stmt = nullptr;
    if(sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        util::error("database::query > prepare: ", sqlite3_errmsg(db_), " [", sql.substr(0, 60), "]");
        return false;
    }
    for(size_t i = 0; i < params.size(); i++) {
        int idx = static_cast<int>(i) + 1;
        if(const int64_t* v = std::get_if<int64_t>(&params[i])) {
            sqlite3_bind_int64(stmt, idx, *v);
        } else {
            sqlite3_bind_text(stmt, idx, std::get<std::string>(params[i]).c_str(), -1, SQLITE_TRANSIENT);
        }
    }
    int rc;
    while((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        on_row(row{stmt});
    }
    bool ok = (rc == SQLITE_DONE);
    if(!ok) {
        util::error("database::query > step: ", sqlite3_errmsg(db_), " [", sql.substr(0, 60), "]");
    }
    sqlite3_finalize(stmt);
    return ok;
}

bool database::start_worker() {
    if(db_ == nullptr || worker_.joinable()) return false;
    if((done_fd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC)) == -1) {
        util::error("database::start_worker > eventfd: ", std::strerror(errno));
        return false;
    }
    stop_ = false;
    worker_ = std::thread(&database::worker_main, this);
    util::info("[db] worker started");
    return true;
}

bool database::exec_async(std::string sql, std::vector<param> params, std::string tag) {
    if(!worker_.joinable()) return false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        jobs_.push_back(job{std::move(sql), std::move(params), std::move(tag)});
    }
    cv_.notify_one();
    return true;
}

// 워커 스레드. 큐에서 하나 꺼내 실행하고 결과를 results_에 넣은 뒤 eventfd로 알린다.
// stop_이 켜져도 큐가 빌 때까지는 돈다 (종료 직전에 넣은 기록을 잃지 않기 위해)
void database::worker_main() {
    sigset_t all;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, nullptr);	// 시그널은 메인 스레드의 signalfd만 받는다

    for(;;) {
        job j;
        {
            std::unique_lock<std::mutex> lock(mu_);
            cv_.wait(lock, [this] { return stop_ || !jobs_.empty(); });
            if(jobs_.empty()) return;	// stop_ && empty
            j = std::move(jobs_.front());
            jobs_.pop_front();
        }
        result r{true, std::move(j.tag), {}};
        r.ok = run(j.sql, j.params, r.err);
        {
            std::lock_guard<std::mutex> lock(mu_);
            results_.push_back(std::move(r));
        }
        uint64_t one = 1;
        if(write(done_fd_, &one, sizeof(one)) != static_cast<ssize_t>(sizeof(one))) {
            // 카운터 포화(EAGAIN)면 이미 신호가 쌓여 있으니 reap()이 결과를 다 가져간다. 무시
        }
    }
}

void database::reap() {
    std::deque<result> done;
    {
        std::lock_guard<std::mutex> lock(mu_);
        done.swap(results_);
    }
    for(const result& r : done) {
        if(r.ok) {
            util::debug("[db] ok: ", r.tag);
        } else {
            util::warn("[db] FAILED: ", r.tag, ": ", r.err);
        }
    }
}

size_t database::pending() const {
    std::lock_guard<std::mutex> lock(mu_);
    return jobs_.size();
}

}
