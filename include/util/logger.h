#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <ostream>
#include <string>

// 콘솔(stdout) 출력. 이 줄을 주석 처리하면 파일에만 쓴다 (log_open()으로 연 파일이 없으면 아무 데도 안 나감).
// systemd로 돌릴 때는 stdout이 journal로 가서 파일과 중복되므로 끄거나 유닛에서 StandardOutput=null.
#define LOG_TO_CONSOLE 1

namespace RS::util {

/**
 * 로그 레벨.
 *   error : 치명적. 프로세스가 멈추거나 핵심 기능(차단)이 안 되는 상황
 *   warn  : 실패했지만 계속 동작함 (nft add element 실패, 일시적 recv 오류)
 *   info  : 운영자가 봐야 할 사실 (기동, 객체 생성, 화이트리스트, 감지, 차단, 메모리, 종료)
 *   debug : 디버깅용 (통과한 패킷 등)
 * set_log_level()로 정한 레벨 미만은 버린다. 기본 info.
 */
enum class log_level : int {
    debug = 0, info, warn, error
};

void set_log_level(log_level lv);	// 이 레벨 미만은 출력하지 않음. 기본 info
log_level get_log_level();
bool set_log_level_from_env();	// GUARD_LOG_LEVEL=debug|info|warn|error 가 있으면 적용. 적용했으면 true
const char* log_level_tag(log_level lv);	// 출력용, 5자 고정폭 ("INFO ")
const char* log_level_name(log_level lv);	// 소문자 이름 ("info")
std::string now_yyyymmddhhmmss();	// 로그 타임스탬프 "2026-10-22 20:19:21" (localtime)

bool log_open(const char* path);	// 파일에도 기록 시작. path에 오늘 날짜를 끼운 파일(logs/guard.2026-10-23.log)을 연다. 디렉터리가 없으면 만든다. 실패하면 false (stdout은 계속)
void log_close();	// 파일을 닫는다. 이후는 stdout만
void log_rotate_if_needed();	// 날짜가 바뀌었으면 새 날짜 파일로 바꾸고 오래된 파일을 지운다. timerHandler가 틱마다 부른다. 던지지 않음
void set_log_keep_days(int days);	// 날짜별 파일 보관 일수. 0이면 지우지 않음. 리로드에서도 씀
void log_flush();	// stdout과 파일 모두 flush. fork 전에 호출

namespace detail {
std::ostream* log_file();	// 열려 있으면 파일 스트림, 아니면 nullptr
}

/**
 * 타임스탬프와 레벨 태그를 붙여 stdout(LOG_TO_CONSOLE이 정의된 때)에 출력하고, log_open()으로 파일을 열어 두었으면 파일에도 같이 쓴다.
 * 파일 쪽은 줄마다 flush해서 프로세스가 갑자기 죽어도 마지막 로그가 남는다.
 * std::ostream은 기본 설정에서 예외를 던지지 않으므로 루프 경로에서 써도 된다.
 */
template<typename... T>
void log_at(log_level lv, const T&... args) {
    if(lv < get_log_level()) return;
    std::string ts = now_yyyymmddhhmmss();
    const char* tag = log_level_tag(lv);
#ifdef LOG_TO_CONSOLE
    std::cout << "[" << ts << "] [" << tag << "] ";
    (std::cout << ... << args);
    std::cout << '\n';
#endif
    if(std::ostream* f = detail::log_file()) {
        *f << "[" << ts << "] [" << tag << "] ";
        (*f << ... << args);
        *f << std::endl;
    }
}

template<typename... T> void debug(const T&... args) { log_at(log_level::debug, args...); }
template<typename... T> void info(const T&... args)  { log_at(log_level::info,  args...); }
template<typename... T> void warn(const T&... args)  { log_at(log_level::warn,  args...); }
template<typename... T> void error(const T&... args) { log_at(log_level::error, args...); }

}
#endif
