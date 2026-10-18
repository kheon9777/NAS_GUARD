#include <string>
#include <chrono>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <iostream>

static std::string to_string_ms(const std::chrono::system_clock::time_point& tp) {
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    struct tm tm_buf;
    localtime_r(&t, &tm_buf);

    long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       tp.time_since_epoch()).count() % 1000;

    char buf[32];
    std::size_t len = std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    std::snprintf(buf + len, sizeof(buf) - len, ".%03lld", ms);
    return std::string(buf);
}

class ICMP_history
{
private:
    std::chrono::system_clock::time_point lastconnect_systime_;
    std::chrono::steady_clock::time_point from_steadytime_;
    int maintain_time_;
    char src_[INET_ADDRSTRLEN];
    int limit_duration_;
    int limit_count_;
    int limit_counter_;
    bool is_time_over_;
    bool is_limit_over_;
public:
    ICMP_history() = delete;
    explicit ICMP_history(int maintain_time, int limit_duration, int limit_count, const iphdr* ip) 
    : maintain_time_(maintain_time), limit_duration_(limit_duration), limit_count_(limit_count),
    limit_counter_(0), is_time_over_(false), is_limit_over_(false) 
    {
        // std::cout << "created\n";
        inet_ntop(AF_INET, &ip->saddr, src_, sizeof(src_));
        update_time();
    }
    ~ICMP_history() {
        // std::cout << "deleted [" << src_ << "] " << to_string_ms(lastconnect_systime_) << "\n";
    }
    void update_time(void) {
        from_steadytime_ = std::chrono::steady_clock::now();
        lastconnect_systime_ = std::chrono::system_clock::now();
    }
    const char* src(void) const {
        return src_;
    }
    // TODO check 2개로 분리해야함 limit_counter가 올라감
    ICMP_history& check(void) {
        std::chrono::duration<double> duration = std::chrono::steady_clock::now() - from_steadytime_;
        is_time_over_ = duration.count() > static_cast<double>(maintain_time_);
        if(duration.count() < static_cast<double>(limit_duration_)) {
            limit_counter_++;
            if(limit_counter_ > limit_count_) {
                is_limit_over_ = true;
            } else {
                is_limit_over_ = false;
            }
        } else {
            limit_counter_ = 0;
            is_limit_over_ = false;
        }
        return *this;
    }
    bool is_time_over(void) const {
        return is_time_over_;
    }
    bool is_limit_over(void) const {
        return is_limit_over_;
    }

    friend std::ostream& operator << (std::ostream& os, const ICMP_history& obj) {
        os << "[" << obj.src_ << "] lastConnect:" << to_string_ms(obj.lastconnect_systime_) << " cnt:" << obj.limit_counter_ << "\n";
        return os;
    } 
};
