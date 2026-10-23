#ifndef RAWSOCK_H
#define RAWSOCK_H

#include <memory>

#include "packet/frame_RS.h"

namespace RS::scnet {

int ready_rawsock();	// AF_PACKET SOCK_RAW ETH_P_ALL 소켓. root 필요. 실패하면 std::system_error (초기화 단계)
void close_rawsock(int fd);
/**
 * 프레임 하나를 recvfrom()으로 받아 parse_frame()에 넘긴다. 아웃바운드(PACKET_OUTGOING)는 rescode 1로 건너뜀.
 * recvfrom 실패는 rescode -2이고 errno를 보존해서 호출자가 치명 여부(EBADF 등)를 판단한다.
 */
std::unique_ptr<packet::frame_RS> rawsock_recv(int fd, int& rescode);

}

#endif
