#ifndef MAC_H
#define MAC_H

#include <cstdint>

namespace RS::packet {

/**
 * MAC 주소는 6바이트를 uint64_t 하나에 담아 다룬다 (map 키, 비교가 쉬움). 0은 "없음"으로 쓴다.
 */
constexpr int MAC_STR_LEN = 18;	// "aa:bb:cc:dd:ee:ff" + NUL

uint64_t mac_pack(const uint8_t* bytes6);	// 6바이트 -> uint64_t (첫 바이트가 상위)
void mac_to_str(uint64_t mac, char* out);	// out은 MAC_STR_LEN 이상. 할당 없음 (루프 경로용)
bool mac_from_str(const char* str, uint64_t& out);	// "aa:bb:cc:dd:ee:ff" 형식이 아니면 false

}

#endif
