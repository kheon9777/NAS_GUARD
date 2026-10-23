#include "store/block_store.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string>

namespace RS::store {

static const char* CREATE_SQL =
    "CREATE TABLE IF NOT EXISTS tbl_block ("
    "  id     INTEGER PRIMARY KEY,"
    "  time   INTEGER NOT NULL,"	// 유닉스 초
    "  ip     TEXT    NOT NULL,"
    "  reason TEXT    NOT NULL"	// tcp_syn_flood, icmp_flood, port_scan
    ");"
    "CREATE INDEX IF NOT EXISTS idx_block_time ON tbl_block(time);";

bool ensure_block_table(database& db) {
    return db.exec(CREATE_SQL);
}

void block_insert_async(database& db, uint32_t ip, const char* reason, int64_t now) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, buf, sizeof(buf));
    db.exec_async("INSERT INTO tbl_block (time, ip, reason) VALUES (?, ?, ?);",
        {now, std::string(buf), std::string(reason)}, std::string("block ") + buf);
}

}
