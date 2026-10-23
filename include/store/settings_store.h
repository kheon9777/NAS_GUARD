#ifndef SETTINGS_STORE_H
#define SETTINGS_STORE_H

#include "settings.h"
#include "store/database.h"

namespace RS::store {

/**
 * tbl_config_info에서 설정을 읽어 out을 채운다. 설정 하나가 컬럼 하나이고 행은 id = 1 하나만 둔다.
 * 테이블이 없으면 만들고, 행이 없으면 out의 기본값으로 한 행을 넣는다 (그 뒤 sqlite3로 UPDATE 해서 바꾼다).
 * 초기화 단계용, 동기. 실패하면 로그 남기고 false.
 */
bool load_settings(database& db, settings& out);

}

#endif
