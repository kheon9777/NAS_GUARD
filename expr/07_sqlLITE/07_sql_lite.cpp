// 설치: sudo apt install libsqlite3-dev sqlite3
// 실행: ./sqlite_example        (같은 폴더에 guard.db 생성)

#include <sqlite3.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

// DB 연결을 소유하는 RAII 클래스
class Database {
public:
    explicit Database(const char* path) {
        if (sqlite3_open(path, &db_) != SQLITE_OK) {
            std::string msg = sqlite3_errmsg(db_);
            sqlite3_close(db_);
            throw std::runtime_error("open: " + msg);
        }
        exec("PRAGMA journal_mode=WAL;");     // 쓰는 중에도 다른 프로세스가 읽을 수 있게(나중에 웹이랑 같이 읽어야됨)
        exec("PRAGMA busy_timeout=3000;");    // 잠겨 있으면 최대 3초까지 기다림
    }

    ~Database() {
        sqlite3_close(db_);
    }

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    // 결과가 필요 없는 SQL 실행 (CREATE, BEGIN, COMMIT 등)
    void exec(const char* sql) {
        char* err = nullptr;
        if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
            std::string msg = (err != nullptr) ? err : "unknown";
            sqlite3_free(err);
            throw std::runtime_error("exec: " + msg);
        }
    }

    sqlite3* handle() const {
        return db_;
    }

private:
    sqlite3* db_ = nullptr;
};

// 준비된 SQL 문을 소유하는 RAII 클래스
class Statement {
public:
    Statement(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("prepare: ") + sqlite3_errmsg(db));
        }
    }

    ~Statement() {
        sqlite3_finalize(stmt_);
    }

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    sqlite3_stmt* get() const {
        return stmt_;
    }

private:
    sqlite3_stmt* stmt_ = nullptr;
};

// 재부팅해도 의미가 유지되는 실제 시각 (유닉스 초)
int64_t unix_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void create_schema(Database& db) {
    db.exec(
        "CREATE TABLE IF NOT EXISTS blocks ("
        "  id         INTEGER PRIMARY KEY,"
        "  ip         TEXT    NOT NULL,"
        "  started_at INTEGER NOT NULL,"
        "  expires_at INTEGER NOT NULL,"
        "  reason     TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_blocks_expires ON blocks(expires_at);");
}

void insert_block(Database& db, const char* ip, int64_t started_at,
                  int64_t expires_at, const char* reason) {
    Statement stmt(db.handle(),
                   "INSERT INTO blocks (ip, started_at, expires_at, reason) VALUES (?, ?, ?, ?);");

    // ? 자리에 값 채우기 (번호는 1부터)
    sqlite3_bind_text(stmt.get(), 1, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 2, started_at);
    sqlite3_bind_int64(stmt.get(), 3, expires_at);
    sqlite3_bind_text(stmt.get(), 4, reason, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw std::runtime_error(std::string("insert: ") + sqlite3_errmsg(db.handle()));
    }
}

// 아직 만료되지 않은 차단 목록 출력 (재시작 시 nft 복원에 쓰는 쿼리)
void print_active_blocks(Database& db, int64_t now) {
    Statement stmt(db.handle(),
                   "SELECT ip, expires_at, reason FROM blocks WHERE expires_at > ? ORDER BY expires_at;");
    sqlite3_bind_int64(stmt.get(), 1, now);

    int rc = sqlite3_step(stmt.get());
    while (rc == SQLITE_ROW) {
        const char* ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        int64_t expires_at = sqlite3_column_int64(stmt.get(), 1);
        const char* reason = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));

        std::printf("%s remaining=%llds reason=%s\n",
                    ip,
                    static_cast<long long>(expires_at - now),
                    (reason != nullptr) ? reason : "-");
        // 실제 프로그램에서는 여기서 block_ip(ip, expires_at - now) 호출

        rc = sqlite3_step(stmt.get());
    }
    if (rc != SQLITE_DONE) {
        throw std::runtime_error(std::string("select: ") + sqlite3_errmsg(db.handle()));
    }
}

int main() {
    try {
        Database db("guard.db");
        create_schema(db);

        int64_t now = unix_now();

        // 여러 건을 쓸 때는 트랜잭션으로 묶어서 한 번에 디스크에 반영
        db.exec("BEGIN;");
        insert_block(db, "10.99.0.2", now, now + 60, "port_scan ports=16");
        insert_block(db, "10.99.0.3", now - 120, now - 60, "icmp_flood");   // 이미 만료된 차단
        db.exec("COMMIT;");

        std::printf("active blocks:\n");
        print_active_blocks(db, now);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }
    return 0;
}