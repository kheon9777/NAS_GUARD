#ifndef DEVICE_TRACKER_H
#define DEVICE_TRACKER_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <unordered_map>
#include <vector>

namespace RS::detect {

/**
 * 장비 감지 설정. 시각은 전부 유닉스 초(int64_t)다. DB에 그대로 넣고 사람이 읽어야 해서 steady_clock을 쓰지 않는다.
 */
struct device_config {
    int64_t expire_s = 0;	// 이 시간 동안 안 보이면 목록에서 제거. 0이면 제거하지 않음
    int64_t spoof_window_s = 60;	// 같은 IP의 MAC이 이 시간 안에
    uint32_t spoof_threshold = 3;	// 이 횟수 이상 바뀌면 스푸핑 의심
};

// 장비 하나. tbl_device 한 행과 같다
struct device {
    uint64_t mac;
    uint32_t ip;	// 마지막으로 본 IP (네트워크 순서)
    int64_t first_seen;
    int64_t last_seen;
    bool dirty;	// DB에 아직 안 쓴 last_seen/ip 변경이 있음
};

enum class device_event {
    none,
    mac_changed,	// 알던 IP의 MAC이 바뀜. 한 번이면 DHCP 재배정 등 정상일 수 있음
    arp_spoof	// 짧은 시간에 여러 번 바뀜. 진짜 장비와 공격자가 번갈아 ARP를 뿌리는 모양
};

// feed() 결과. new_device와 event는 동시에 켜질 수 있다
struct feed_result {
    bool new_device = false;	// 처음 보는 MAC
    device_event event = device_event::none;
    uint64_t old_mac = 0;	// mac_changed / arp_spoof 일 때 직전 MAC
    const device* dev = nullptr;	// 이번 프레임의 장비. 다음 feed() 전까지만 유효
};

/**
 * LAN 장비 목록. ARP의 sender(MAC, IP)만 먹인다. ARP는 라우터를 넘지 않아 같은 LAN 장비만 보이므로 따로 거를 필요가 없다.
 * (IP 패킷은 쓰지 않는다: 공유기를 거쳐 온 외부 패킷은 출발지 MAC이 전부 공유기라 장비로 오해하게 된다.)
 * MAC이 장비의 신원이고, IP -> MAC 소유 관계를 따로 들어 스푸핑을 본다.
 * 차단은 하지 않는다 (IP로 막으면 피해자를 막고, DHCP 재배정과 구분이 안 됨). 이벤트만 돌려준다.
 */
class device_tracker {
private:
    struct owner {
        uint64_t mac = 0;
        std::deque<int64_t> changes;	// MAC이 바뀐 시각들 (window 안)
        int64_t last_alarm = 0;	// 스푸핑 알람은 window당 한 번만
    };
    device_config cfg_;
    std::unordered_map<uint64_t, device> devices_;	// MAC -> 장비
    std::unordered_map<uint32_t, owner> owners_;	// IP -> 그 IP를 쓰는 MAC
public:
    explicit device_tracker(const device_config& cfg);
    void reconfigure(const device_config& cfg);	// 리로드. 장비 목록은 유지
    void restore(uint64_t mac, uint32_t ip, int64_t first_seen, int64_t last_seen);	// 시작 때 DB에서
    feed_result feed(uint64_t mac, uint32_t ip, int64_t now);	// ARP 프레임마다 호출 (sender MAC, sender IP)
    void expire(int64_t now, std::vector<device>& removed);	// 오래 안 보인 장비 제거. removed에 담아 줌 (DB 삭제용). expire_s가 0이면 아무것도 안 함
    void take_dirty(std::vector<device>& out);	// dirty 장비를 꺼내고 플래그를 지움 (DB 갱신용)
    size_t size() const { return devices_.size(); }	// 추적 중인 장비 수 (메모리 로그용)
};

}

#endif
