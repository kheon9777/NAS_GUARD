#ifndef PROCINFO_H
#define PROCINFO_H

namespace RS::util {

/**
 * 현재 프로세스의 RSS(실제 메모리 사용량)를 KB로 돌려준다. /proc/self/statm 기준.
 * 읽기 실패면 -1. 예외를 던지지 않는다.
 */
long rss_kb();

}

#endif
