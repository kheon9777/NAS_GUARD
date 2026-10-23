#ifndef BLOCK_STORE_H
#define BLOCK_STORE_H

#include <cstdint>

#include "store/database.h"

namespace RS::store {

/**
 * 차단 기록 tbl_block (time, ip, reason). 차단할 때마다 한 행. 웹에서 열람용이라 간단히만 남긴다.
 * ensure_block_table()만 동기(초기화). insert는 exec_async()로 큐에 넣고 바로 돌아온다 (루프 경로).
 */
bool ensure_block_table(database& db);
void block_insert_async(database& db, uint32_t ip, const char* reason, int64_t now);	// ip는 네트워크 순서, reason은 verdict_name()

}

#endif
