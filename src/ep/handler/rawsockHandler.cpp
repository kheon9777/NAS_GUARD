// simple_dump.cpp
// 빌드: g++ -std=c++17 -Wall -Wextra -o simple_dump simple_dump.cpp
// 실행: sudo ./simple_dump

#include <unistd.h>
#include <iostream>
#include <string>

#include "util/logger.h"
#include "ep/handler/eventHandler.h"
#include "ep/handler/rawsockHandler.h"
#include "scnet/rawsock.h"

namespace RS::ep {
    rawsockHandler::rawsockHandler() : fd_(-1) {    // TODO : 차단 ip목록 등에 대해 생성자 주입
        if((fd_ = scnet::ready_rawsock()) == -1) {
            throw std::system_error(errno, std::generic_category(), "rawsockHandler > construc > socket");
        }
        util::logger("rawsockHandler created");
    }
    rawsockHandler::~rawsockHandler() { 
        close(fd_);
    }
    int rawsockHandler::fd() const {
        return fd_;
    }
    eventHandlerResult rawsockHandler::on_readable() noexcept {
        scnet::rawsock_do(fd_);
        return eventHandlerResult::ok;
    }
}
