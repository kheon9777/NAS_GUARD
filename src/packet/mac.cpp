#include "packet/mac.h"

#include <cstdio>

namespace RS::packet {

uint64_t mac_pack(const uint8_t* b) {
    uint64_t v = 0;
    for(int i = 0; i < 6; i++) {
        v = (v << 8) | b[i];
    }
    return v;
}

void mac_to_str(uint64_t mac, char* out) {
    std::snprintf(out, MAC_STR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
        static_cast<unsigned>((mac >> 40) & 0xff), static_cast<unsigned>((mac >> 32) & 0xff),
        static_cast<unsigned>((mac >> 24) & 0xff), static_cast<unsigned>((mac >> 16) & 0xff),
        static_cast<unsigned>((mac >> 8) & 0xff), static_cast<unsigned>(mac & 0xff));
}

bool mac_from_str(const char* str, uint64_t& out) {
    unsigned b[6];
    if(std::sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        return false;
    }
    out = 0;
    for(int i = 0; i < 6; i++) {
        out = (out << 8) | (b[i] & 0xff);
    }
    return true;
}

}
