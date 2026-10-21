#include "ep/handler/rawsockHandler.h"

#include <iostream>
#include <string>

#include "util/logger.h"
#include "ep/handler/eventHandler.h"
#include "scnet/rawsock.h"

namespace RS::ep {
    rawsockHandler::rawsockHandler() : fd_(-1) {    // TODO : 차단 ip목록 등에 대해 생성자 주입, 필드에 ip관리 클래스 레퍼런스를 가질 예정
        if((fd_ = scnet::ready_rawsock()) == -1) {
            throw std::system_error(errno, std::generic_category(), "rawsockHandler > construc > socket");
        }
        util::logger("rawsockHandler created");
    }
    rawsockHandler::~rawsockHandler() { 
        scnet::close_rawsock(fd_);
    }
    int rawsockHandler::fd() const {
        return fd_;
    }
    eventHandlerResult rawsockHandler::on_readable() noexcept {
        scnet::rawsock_do(fd_);
        return eventHandlerResult::ok;
    }
}
