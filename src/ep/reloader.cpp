#include "ep/reloader.h"

#include <utility>

#include "store/settings_store.h"
#include "store/whitelist_store.h"
#include "util/logger.h"

namespace RS::ep {

detect::device_config make_device_config(const settings& s) {
    detect::device_config out;
    out.expire_s = s.device_expire.count();
    out.spoof_window_s = s.arp_spoof_window.count();
    out.spoof_threshold = s.arp_spoof_threshold;
    return out;
}

reloader::reloader(store::database& db, settings& cfg, detect::analyzer& anyz, detect::device_tracker& devices,
block::blocker& blocker, block::whitelist& wlist, epoll_RS& ep, timerHandler& timer)
: db_(db), cfg_(cfg), anyz_(anyz), devices_(devices), blocker_(blocker), wlist_(wlist), ep_(ep), timer_(timer) {
}

void reloader::reload() noexcept {
    reload_settings();
    reload_whitelist();
}

void reloader::reload_settings() noexcept {
    settings fresh;
    if(!store::load_settings(db_, fresh)) {
        util::error("[reload] settings load failed, keeping current");
        return;
    }
    anyz_.reconfigure(detect::config{fresh});
    devices_.reconfigure(make_device_config(fresh));
    blocker_.set_timeout(fresh.block_timeout);
    ep_.set_timeout(fresh.loop_timeout_ms);
    timer_.set_interval(fresh.expire_interval);
    timer_.set_mem_log_every(fresh.mem_log_every_ticks);
    util::set_log_keep_days(fresh.log_keep_days);
    if(fresh.nft_family != cfg_.nft_family || fresh.nft_table != cfg_.nft_table || fresh.nft_set != cfg_.nft_set
    || fresh.nft_chain != cfg_.nft_chain || fresh.nft_priority != cfg_.nft_priority || fresh.log_path != cfg_.log_path) {
        util::warn("[reload] nft_* or log_path changed: takes effect after restart");
    }
    cfg_ = fresh;
    util::info("[reload] settings applied: ", cfg_.summary());
}

// 새 목록을 따로 채운 뒤 전부 성공했을 때만 교체한다. 항목 하나라도 잘못되면 기존 목록 유지 (내 IP가 빠지면 접속이 끊김)
void reloader::reload_whitelist() noexcept {
    block::whitelist fresh;
    if(!store::load_whitelist(db_, fresh)) {
        util::error("[reload] whitelist load failed, keeping current (", wlist_.size(), " entries)");
        return;
    }
    wlist_ = std::move(fresh);
    util::info("[reload] whitelist applied: ", wlist_.size(), " entries");
}

}
