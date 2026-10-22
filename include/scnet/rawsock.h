#ifndef RAWSOCK_H
#define RAWSOCK_H

#include <memory>

#include "packet/ip_RS.h"

namespace RS::scnet {

int ready_rawsock();
void close_rawsock(int fd);
std::unique_ptr<packet::ip_RS> rawsock_recv(int fd, int& rescode);

}

#endif
