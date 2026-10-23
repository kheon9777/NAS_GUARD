#include "util/procinfo.h"

#include <unistd.h>
#include <cstdio>

namespace RS::util {
long rss_kb() {
    // statm: size resident shared text lib data dt  (단위: 페이지)
    FILE* f = std::fopen("/proc/self/statm", "r");
    if(f == nullptr) return -1;
    long size = 0;
    long resident = 0;
    int n = std::fscanf(f, "%ld %ld", &size, &resident);
    std::fclose(f);
    if(n != 2) return -1;
    return resident * (sysconf(_SC_PAGESIZE) / 1024);
}
}
