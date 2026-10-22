#ifndef EPOLL_LOOP_H
#define EPOLL_LOOP_H

namespace RS::ep {
/**
 * 반환값은 프로세스 exit code로 쓴다.
 * 0 : SIGTERM 등으로 정상 종료
 * 1 : 치명적 오류 (초기화 실패, epoll_wait 실패). systemd Restart=on-failure가 재시작하도록 0이 아닌 값
 */
int do_loop();
void set_g_working(bool val);
}
#endif
