#include "util/logger.h"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <system_error>

namespace RS::util {
static std::ofstream g_log_file;
static log_level g_level = log_level::info;
static std::filesystem::path g_log_base;	// log_open()이 받은 경로 (logs/guard.log). 실제 파일명은 여기에 날짜를 끼움
static std::string g_log_date;	// 지금 열려 있는 파일의 날짜 "2026-10-23". 비어 있으면 안 열림
static int g_log_keep_days = 0;	// 0이면 오래된 파일을 지우지 않음

void set_log_level(log_level lv) {
    g_level = lv;
}
log_level get_log_level() {
    return g_level;
}
bool set_log_level_from_env() {
    const char* v = std::getenv("GUARD_LOG_LEVEL");
    if(v == nullptr) return false;
    if(std::strcmp(v, "debug") == 0)      g_level = log_level::debug;
    else if(std::strcmp(v, "info") == 0)  g_level = log_level::info;
    else if(std::strcmp(v, "warn") == 0)  g_level = log_level::warn;
    else if(std::strcmp(v, "error") == 0) g_level = log_level::error;
    else return false;
    return true;
}
const char* log_level_tag(log_level lv) {
    switch(lv) {
    case log_level::debug: return "DEBUG";
    case log_level::info:  return "INFO ";
    case log_level::warn:  return "WARN ";
    case log_level::error: return "ERROR";
    }
    return "?????";
}
const char* log_level_name(log_level lv) {
    switch(lv) {
    case log_level::debug: return "debug";
    case log_level::info:  return "info";
    case log_level::warn:  return "warn";
    case log_level::error: return "error";
    }
    return "?";
}

std::string now_yyyymmddhhmmss() {
    std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm_buf{};
    localtime_r(&t, &tm_buf);

    char buf[20];	// "20261020 15:24:30" 15글자 + \0
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return std::string(buf);
}

static std::string today_yyyymmdd() {	// "2026-10-23" (localtime). 파일명과 비교에 씀
    std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm_buf{};
    localtime_r(&t, &tm_buf);
    char buf[11];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_buf);
    return std::string(buf);
}

// logs/guard.log + "2026-10-23" -> logs/guard.2026-10-23.log. 확장자가 없으면 logs/guard.2026-10-23
static std::filesystem::path dated_path(const std::filesystem::path& base, const std::string& date) {
    std::filesystem::path p = base;
    p.replace_filename(base.stem().string() + "." + date + base.extension().string());
    return p;
}

// 같은 디렉터리의 <stem>.YYYY-MM-DD<ext> 중 날짜가 cutoff보다 앞선 파일을 지운다. 날짜는 파일명에서 읽는다 (mtime은 복사하면 바뀜).
// 날짜 없는 옛 파일(guard.log)은 건드리지 않는다. 던지지 않음 (error_code 버전만 씀)
static void remove_old_logs() {
    if(g_log_keep_days <= 0 || g_log_base.empty()) return;
    std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    t -= static_cast<std::time_t>(g_log_keep_days) * 86400;
    std::tm tm_buf{};
    localtime_r(&t, &tm_buf);
    char cutoff[11];
    std::strftime(cutoff, sizeof(cutoff), "%Y-%m-%d", &tm_buf);

    const std::string prefix = g_log_base.stem().string() + ".";
    const std::string ext = g_log_base.extension().string();
    std::filesystem::path dir = g_log_base.has_parent_path() ? g_log_base.parent_path() : std::filesystem::path{"."};
    std::error_code ec;
    for(const auto& entry : std::filesystem::directory_iterator{dir, ec}) {
        if(ec) break;
        std::string name = entry.path().filename().string();
        if(name.size() != prefix.size() + 10 + ext.size()) continue;
        if(name.compare(0, prefix.size(), prefix) != 0) continue;
        if(name.compare(name.size() - ext.size(), ext.size(), ext) != 0) continue;
        std::string date = name.substr(prefix.size(), 10);
        if(date[4] != '-' || date[7] != '-') continue;
        if(date < cutoff) {	// "YYYY-MM-DD"는 문자열 비교가 날짜 순서와 같다
            std::error_code rm_ec;
            if(std::filesystem::remove(entry.path(), rm_ec)) {
                info("[log] removed old log ", name);
            } else {
                warn("[log] remove failed ", name, ": ", rm_ec.message());
            }
        }
    }
}

bool log_open(const char* path) {
    log_close();
    g_log_base = path;
    if(g_log_base.has_parent_path()) {
        std::error_code ec;	// 예외 대신 error_code 버전
        std::filesystem::create_directories(g_log_base.parent_path(), ec);
    }
    std::string date = today_yyyymmdd();
    g_log_file.open(dated_path(g_log_base, date), std::ios::app);
    if(!g_log_file.is_open()) return false;
    g_log_date = date;
    remove_old_logs();
    return true;
}

void log_close() {
    if(g_log_file.is_open()) {
        g_log_file.close();
    }
    g_log_date.clear();
}

void set_log_keep_days(int days) {
    g_log_keep_days = days;
}

void log_rotate_if_needed() {
    if(g_log_date.empty()) return;	// 파일 로그를 안 쓰는 중
    std::string date = today_yyyymmdd();
    if(date == g_log_date) return;
    info("[log] date changed, continuing in ", dated_path(g_log_base, date).string());	// 옛 파일의 마지막 줄
    std::filesystem::path base = g_log_base;
    if(!log_open(base.c_str())) {
        warn("[log] reopen failed for ", dated_path(base, date).string(), " (stdout only)");
    }
}

void log_flush() {
#ifdef LOG_TO_CONSOLE
    std::cout.flush();
#endif
    if(g_log_file.is_open()) {
        g_log_file.flush();
    }
}

namespace detail {
std::ostream* log_file() {
    return g_log_file.is_open() ? &g_log_file : nullptr;
}
}

}
