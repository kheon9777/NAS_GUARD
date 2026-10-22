// logger.cpp
#include "util/logger.h"

#include <chrono>
#include <ctime>

namespace RS::util {
std::string now_yyyymmddhhmmss() {
    std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm_buf{};
    localtime_r(&t, &tm_buf);

    char buf[20];  // "20261020 15:24:30" 15글자 + \0
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return std::string(buf);
}
}