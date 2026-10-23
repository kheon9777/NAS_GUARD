#include "store/settings_store.h"

#include <chrono>
#include <cstdint>
#include <string>

#include "util/logger.h"

namespace RS::store {

static const char* CREATE_SQL =
    "CREATE TABLE IF NOT EXISTS tbl_config_info ("
    "  id                  INTEGER PRIMARY KEY CHECK(id = 1),"	// 행 하나만
    "  scan_window_s       INTEGER NOT NULL,"
    "  scan_threshold      INTEGER NOT NULL,"
    "  tcp_rate_window_s   INTEGER NOT NULL,"
    "  tcp_rate_threshold  INTEGER NOT NULL,"
    "  icmp_rate_window_s  INTEGER NOT NULL,"
    "  icmp_rate_threshold INTEGER NOT NULL,"
    "  max_horizen         INTEGER NOT NULL,"
    "  block_timeout_s     INTEGER NOT NULL,"
    "  nft_family          TEXT    NOT NULL,"
    "  nft_table           TEXT    NOT NULL,"
    "  nft_set             TEXT    NOT NULL,"
    "  nft_chain           TEXT    NOT NULL,"
    "  nft_priority        INTEGER NOT NULL,"
    "  loop_timeout_ms     INTEGER NOT NULL,"
    "  expire_interval_s   INTEGER NOT NULL,"
    "  mem_log_every_ticks INTEGER NOT NULL,"
    "  log_path            TEXT    NOT NULL,"
    "  updated_at          INTEGER NOT NULL DEFAULT (strftime('%s','now'))"
    ");";

// 나중에 추가된 컬럼. 기존 DB에는 ALTER TABLE로 붙인다 (CREATE IF NOT EXISTS는 컬럼을 안 더함)
struct column_def {
    const char* name;
    const char* decl;	// 타입 + DEFAULT. 기존 행은 DEFAULT 값을 갖는다
};
static const column_def ADDED_COLUMNS[] = {
    {"device_expire_s", "INTEGER NOT NULL DEFAULT 0"},
    {"arp_spoof_window_s", "INTEGER NOT NULL DEFAULT 60"},
    {"arp_spoof_threshold", "INTEGER NOT NULL DEFAULT 3"},
    {"log_keep_days", "INTEGER NOT NULL DEFAULT 7"},
};

static bool ensure_column(database& db, const column_def& c) {
    bool exists = false;
    if(!db.query("PRAGMA table_info(tbl_config_info);", {}, [&](const row& r) {
        if(r.text(1) == c.name) exists = true;
    })) return false;
    if(exists) return true;
    util::info("[settings] adding column ", c.name);
    return db.exec(std::string("ALTER TABLE tbl_config_info ADD COLUMN ") + c.name + " " + c.decl + ";");
}

static const char* SELECT_SQL =
    "SELECT scan_window_s, scan_threshold, tcp_rate_window_s, tcp_rate_threshold,"
    " icmp_rate_window_s, icmp_rate_threshold, max_horizen, block_timeout_s,"
    " nft_family, nft_table, nft_set, nft_chain, nft_priority,"
    " loop_timeout_ms, expire_interval_s, mem_log_every_ticks, log_path,"
    " device_expire_s, arp_spoof_window_s, arp_spoof_threshold, log_keep_days"
    " FROM tbl_config_info WHERE id = 1;";

static const char* INSERT_SQL =
    "INSERT INTO tbl_config_info (id, scan_window_s, scan_threshold, tcp_rate_window_s, tcp_rate_threshold,"
    " icmp_rate_window_s, icmp_rate_threshold, max_horizen, block_timeout_s,"
    " nft_family, nft_table, nft_set, nft_chain, nft_priority,"
    " loop_timeout_ms, expire_interval_s, mem_log_every_ticks, log_path,"
    " device_expire_s, arp_spoof_window_s, arp_spoof_threshold, log_keep_days)"
    " VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

static param i64(auto v) {	// variant의 변환 생성자는 축소 변환을 막으므로 명시적으로 int64로
    return param{static_cast<int64_t>(v)};
}

bool load_settings(database& db, settings& out) {
    if(!db.exec(CREATE_SQL)) return false;
    for(const column_def& c : ADDED_COLUMNS) {
        if(!ensure_column(db, c)) return false;
    }

    bool found = false;
    bool ok = db.query(SELECT_SQL, {}, [&](const row& r) {
        found = true;
        out.scan_window = std::chrono::seconds{r.integer(0)};
        out.scan_threshold = static_cast<uint32_t>(r.integer(1));
        out.tcp_rate_window = std::chrono::seconds{r.integer(2)};
        out.tcp_rate_threshold = static_cast<uint32_t>(r.integer(3));
        out.icmp_rate_window = std::chrono::seconds{r.integer(4)};
        out.icmp_rate_threshold = static_cast<uint32_t>(r.integer(5));
        out.max_horizen = static_cast<size_t>(r.integer(6));
        out.block_timeout = std::chrono::seconds{r.integer(7)};
        out.nft_family = r.text(8);
        out.nft_table = r.text(9);
        out.nft_set = r.text(10);
        out.nft_chain = r.text(11);
        out.nft_priority = static_cast<int>(r.integer(12));
        out.loop_timeout_ms = static_cast<int>(r.integer(13));
        out.expire_interval = std::chrono::seconds{r.integer(14)};
        out.mem_log_every_ticks = static_cast<unsigned long>(r.integer(15));
        out.log_path = r.text(16);
        out.device_expire = std::chrono::seconds{r.integer(17)};
        out.arp_spoof_window = std::chrono::seconds{r.integer(18)};
        out.arp_spoof_threshold = static_cast<uint32_t>(r.integer(19));
        out.log_keep_days = static_cast<int>(r.integer(20));
    });
    if(!ok) return false;

    if(found) {
        util::info("[settings] loaded from tbl_config_info");
        return true;
    }
    // 첫 실행: 기본값으로 한 행을 만들어 둔다. 이후에는 이 행을 고쳐서 설정을 바꾼다
    ok = db.exec(INSERT_SQL, {
        i64(out.scan_window.count()), i64(out.scan_threshold),
        i64(out.tcp_rate_window.count()), i64(out.tcp_rate_threshold),
        i64(out.icmp_rate_window.count()), i64(out.icmp_rate_threshold),
        i64(out.max_horizen), i64(out.block_timeout.count()),
        out.nft_family, out.nft_table, out.nft_set, out.nft_chain, i64(out.nft_priority),
        i64(out.loop_timeout_ms), i64(out.expire_interval.count()), i64(out.mem_log_every_ticks),
        out.log_path,
        i64(out.device_expire.count()),
        i64(out.arp_spoof_window.count()), i64(out.arp_spoof_threshold),
        i64(out.log_keep_days),
    });
    if(!ok) return false;
    util::info("[settings] tbl_config_info was empty, defaults inserted");
    return true;
}

}
