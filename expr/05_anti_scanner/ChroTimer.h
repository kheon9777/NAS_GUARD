#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/tcp.h>      
#include <netinet/udp.h>      
#include <netinet/ip_icmp.h>  
#include <chrono>
#include <string>

#include <cstdint>
#include <cstdio>

class ChroTimer
{
private:
    std::chrono::steady_clock::time_point from_;
    std::string tag_;
public:
    // steady clock은 기동시간, 
    // system clock은 시스템 시간 yyyymmdd... 이런거
    explicit ChroTimer(const std::string& tag) : from_(std::chrono::steady_clock::now()), tag_(tag) {
    }
    explicit ChroTimer(std::string&& tag) : from_(std::chrono::steady_clock::now()), tag_(std::move(tag)) {
    }
    const std::string& tag(void) const {
        return tag_;
    }
    void set_tag(const std::string& tag) {
        tag_ = tag;
    }
    void set_tag(std::string&& tag) {
        tag_ = std::move(tag);
    }
    void reset(void) {
        from_ = std::chrono::steady_clock::now();
    }
    double duration(void) const {
        return std::chrono::duration<double>{std::chrono::steady_clock::now() - from_}.count();
    }
};
