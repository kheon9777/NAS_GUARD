#ifndef LOGGER_H
#define LOGGER_H
#include <iostream>
#include <string>

namespace RS::util {
template<typename... T> void logger(const T&...);
std::string now_yyyymmddhhmmss();

template<typename... T>
void logger(const T&... args) {
    std::cout << "[" << now_yyyymmddhhmmss() << "] ";
    (std::cout << ... << args);
    std::cout << '\n';
}
}
#endif
