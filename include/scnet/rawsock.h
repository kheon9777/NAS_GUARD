#ifndef RAWSOCK_H
#define RAWSOCK_H

#include <netinet/ip.h>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "scnet/ip_RS.h"

namespace RS::scnet {

std::unique_ptr<ip_RS> get_ip_RS(const iphdr* ip, const uint8_t* l4,
    const size_t l4avail, const size_t ip_header_len, const size_t tot_len, int& rescode);
int ready_rawsock();
void close_rawsock(int fd);
std::unique_ptr<ip_RS> rawsock_recv(int fd, int& rescode);
int rawsock_do(int fd);

}

#endif