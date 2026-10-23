#ifndef WHITELIST_STORE_H
#define WHITELIST_STORE_H

#include "block/whitelist.h"
#include "store/database.h"

namespace RS::store {

/**
 * 화이트리스트를 처음부터 채운다: whitelist.local.h의 항목 + tbl_whitelist의 모든 행.
 * local 항목은 DB에 넣지 않고 메모리에만 더한다 (개인 IP를 DB 파일에도 남기지 않기 위해).
 * 테이블이 없으면 만든다. 행: ip TEXT, mask TEXT(NULL이면 단일 IP), note TEXT.
 * 잘못된 항목이 하나라도 있으면 false. 호출하는 쪽이 교체 여부를 정한다 (시작 때는 중단, 리로드 때는 기존 유지).
 */
bool load_whitelist(database& db, block::whitelist& out);

}

#endif
