#ifndef DEVICE_STORE_H
#define DEVICE_STORE_H

#include <cstdint>

#include "detect/device_tracker.h"
#include "store/database.h"

namespace RS::store {

/**
 * 장비 목록(tbl_device)과 장비 이벤트(tbl_device_event).
 * load_devices()만 동기(초기화). 나머지는 exec_async()로 큐에 넣고 바로 돌아온다 (루프 경로).
 * MAC은 "aa:bb:cc:dd:ee:ff" 텍스트로, 시각은 유닉스 초로 저장한다.
 */
bool load_devices(database& db, detect::device_tracker& out);	// 테이블이 없으면 만들고, 행을 tracker에 복원
void device_insert_async(database& db, const detect::device& d);	// 새 장비. INSERT OR REPLACE
void device_update_async(database& db, const detect::device& d);	// ip, last_seen
void device_delete_async(database& db, uint64_t mac);	// 만료된 장비
// type: "new_device", "device_gone", "mac_changed", "arp_spoof"
void device_event_async(database& db, const char* type, uint32_t ip, uint64_t old_mac, uint64_t new_mac, int64_t now);

}

#endif
