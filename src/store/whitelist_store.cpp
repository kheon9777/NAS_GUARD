#include "store/whitelist_store.h"

#include "util/logger.h"

namespace RS::store {

static const char* CREATE_SQL =
    "CREATE TABLE IF NOT EXISTS tbl_whitelist ("
    "  id         INTEGER PRIMARY KEY,"
    "  ip         TEXT NOT NULL,"
    "  mask       TEXT,"	// NULL : 단일 IP
    "  note       TEXT,"
    "  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))"
    ");";

bool load_whitelist(database& db, block::whitelist& out) {
    bool ok = block::load_local_whitelist(out);
    if(!db.exec(CREATE_SQL)) return false;
    bool query_ok = db.query("SELECT ip, mask, note FROM tbl_whitelist ORDER BY id;", {}, [&](const row& r) {
        std::string ip = r.text(0);
        std::string note = r.text(2);
        if(r.is_null(1)) {
            if(out.add(ip)) util::info("[whitelist] db ", ip, " (", note, ")");
            else ok = false;
        } else {
            std::string mask = r.text(1);
            if(out.add(ip, mask)) util::info("[whitelist] db ", ip, "/", mask, " (", note, ")");
            else ok = false;
        }
    });
    return ok && query_ok;
}

}
