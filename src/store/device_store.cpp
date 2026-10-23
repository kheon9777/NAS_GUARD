#include "store/device_store.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string>

#include "packet/mac.h"
#include "util/logger.h"

namespace RS::store {

static const char* CREATE_SQL =
    "CREATE TABLE IF NOT EXISTS tbl_device ("
    "  mac        TEXT PRIMARY KEY,"
    "  ip         TEXT NOT NULL,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  name       TEXT,"	// 사람이 붙이는 이름 (관제용)
    "  note       TEXT"
    ");"
    "CREATE TABLE IF NOT EXISTS tbl_device_event ("
    "  id      INTEGER PRIMARY KEY,"
    "  time    INTEGER NOT NULL,"
    "  type    TEXT NOT NULL,"
    "  ip      TEXT,"
    "  old_mac TEXT,"
    "  new_mac TEXT"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_device_event_time ON tbl_device_event(time);";

static std::string mac_s(uint64_t mac) {
    char buf[packet::MAC_STR_LEN];
    packet::mac_to_str(mac, buf);
    return buf;
}
static std::string ip_s(uint32_t ip) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, buf, sizeof(buf));
    return buf;
}

bool load_devices(database& db, detect::device_tracker& out) {
    if(!db.exec(CREATE_SQL)) return false;
    size_t n = 0;
    bool ok = db.query("SELECT mac, ip, first_seen, last_seen FROM tbl_device ORDER BY last_seen;", {}, [&](const row& r) {
        uint64_t mac;
        uint32_t ip;
        if(!packet::mac_from_str(r.text(0).c_str(), mac) || inet_pton(AF_INET, r.text(1).c_str(), &ip) != 1) {
            util::warn("[device] bad row in tbl_device: ", r.text(0), " ", r.text(1));
            return;
        }
        out.restore(mac, ip, r.integer(2), r.integer(3));
        n++;
    });
    if(ok) util::info("[device] ", n, " devices restored from tbl_device");
    return ok;
}

void device_insert_async(database& db, const detect::device& d) {
    db.exec_async("INSERT OR REPLACE INTO tbl_device (mac, ip, first_seen, last_seen) VALUES (?, ?, ?, ?);",
        {mac_s(d.mac), ip_s(d.ip), d.first_seen, d.last_seen}, "device insert " + mac_s(d.mac));
}

void device_update_async(database& db, const detect::device& d) {
    db.exec_async("UPDATE tbl_device SET ip = ?, last_seen = ? WHERE mac = ?;",
        {ip_s(d.ip), d.last_seen, mac_s(d.mac)}, "device update " + mac_s(d.mac));
}

void device_delete_async(database& db, uint64_t mac) {
    db.exec_async("DELETE FROM tbl_device WHERE mac = ?;", {mac_s(mac)}, "device delete " + mac_s(mac));
}

void device_event_async(database& db, const char* type, uint32_t ip, uint64_t old_mac, uint64_t new_mac, int64_t now) {
    db.exec_async("INSERT INTO tbl_device_event (time, type, ip, old_mac, new_mac) VALUES (?, ?, ?, ?, ?);",
        {now, std::string(type), ip_s(ip), mac_s(old_mac), mac_s(new_mac)}, std::string("event ") + type);
}

}
