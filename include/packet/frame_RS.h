#ifndef FRAME_RS_H
#define FRAME_RS_H

#include <cstdint>
#include <ostream>

namespace RS::packet {

// parse_frame()이 만든 객체의 종류. static_cast로 내려갈 때 기준
enum class frame_type {
    ip, arp
};

/**
 * 이더넷 프레임 하나. parse_frame()이 만드는 모든 객체의 베이스.
 * 출발지 MAC(ethhdr::h_source)을 들고 있어서 장비 감지가 L3 종류와 무관하게 읽는다.
 * 출력은 operator<<가 가상 함수 print()를 부른다.
 */
class frame_RS {
private:
    frame_type type_;
    uint64_t src_mac_;	// mac_pack() 형식. 0이면 아직 안 채워짐
protected:
    virtual void print(std::ostream& os) const = 0;	// 하위 클래스가 로그용 한 줄을 쓴다
public:
    explicit frame_RS(frame_type type);	// src_mac은 0. 파서가 set_src_mac()으로 채운다
    virtual ~frame_RS() = default;
    frame_type type() const;
    bool is_type(frame_type val) const;
    uint64_t src_mac() const;	// 이더넷 헤더의 출발지 MAC (mac_pack 형식)
    void set_src_mac(const uint8_t* bytes6);	// ethhdr::h_source를 넣는다
    friend std::ostream& operator << (std::ostream& os, const frame_RS& f);
};

}

#endif
