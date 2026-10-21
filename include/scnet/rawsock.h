#ifndef RAWSOCK_H
#define RAWSOCK_H

namespace RS::scnet {
int ready_rawsock();
void close_rawsock(int fd);
int rawsock_do(int fd);
}

#endif