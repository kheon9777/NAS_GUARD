#include "detect/device_tracker.h"

#include <iterator>

namespace RS::detect {
device_tracker::device_tracker(const device_config& cfg) : cfg_(cfg) {
}
void device_tracker::reconfigure(const device_config& cfg) {
    cfg_ = cfg;
}
void device_tracker::restore(uint64_t mac, uint32_t ip, int64_t first_seen, int64_t last_seen) {
    devices_[mac] = device{mac, ip, first_seen, last_seen, false};
    owner& o = owners_[ip];
    if(o.mac == 0 || devices_[o.mac].last_seen < last_seen) o.mac = mac;	// 같은 IP면 더 최근 장비가 주인
}
feed_result device_tracker::feed(uint64_t mac, uint32_t ip, int64_t now) {
    feed_result r;
    if(mac == 0 || ip == 0) return r;	// ARP probe(0.0.0.0) 등

    auto iter = devices_.find(mac);
    if(iter == devices_.end()) {
        iter = devices_.emplace(mac, device{mac, ip, now, now, false}).first;	// INSERT는 호출자가 하므로 dirty 아님
        r.new_device = true;
    } else {
        device& d = iter->second;
        d.last_seen = now;
        d.ip = ip;
        d.dirty = true;
    }
    r.dev = &iter->second;

    owner& o = owners_[ip];
    if(o.mac == 0) {
        o.mac = mac;
    } else if(o.mac != mac) {
        r.old_mac = o.mac;
        o.mac = mac;
        o.changes.push_back(now);
        while(!o.changes.empty() && now - o.changes.front() > cfg_.spoof_window_s) {
            o.changes.pop_front();
        }
        if(o.changes.size() >= cfg_.spoof_threshold) {
            if(now - o.last_alarm >= cfg_.spoof_window_s) {	// 공격이 계속되면 window마다 한 번씩만
                o.last_alarm = now;
                r.event = device_event::arp_spoof;
            }
        } else {
            r.event = device_event::mac_changed;
        }
    }
    return r;
}
void device_tracker::expire(int64_t now, std::vector<device>& removed) {
    if(cfg_.expire_s <= 0) return;	// 만료 없음: 장비는 한 번 보이면 계속 남는다
    for(auto iter = devices_.begin(); iter != devices_.end();) {
        if(now - iter->second.last_seen > cfg_.expire_s) {
            removed.push_back(iter->second);
            auto o = owners_.find(iter->second.ip);
            if(o != owners_.end() && o->second.mac == iter->first) owners_.erase(o);
            iter = devices_.erase(iter);
        } else {
            ++iter;
        }
    }
}
void device_tracker::take_dirty(std::vector<device>& out) {
    for(auto& [mac, d] : devices_) {
        if(d.dirty) {
            out.push_back(d);
            d.dirty = false;
        }
    }
}
}
