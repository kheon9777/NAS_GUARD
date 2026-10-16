// simple_dump.cpp
// 빌드: g++ -std=c++17 -Wall -Wextra -o simple_dump simple_dump.cpp
// 실행: sudo ./simple_dump

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

class chroTimer
{
private:
    std::chrono::steady_clock::time_point from_;
    std::string tag_;
public:
    // steady clock은 기동시간, 
    // system clock은 시스템 시간 yyyymmdd... 이런거
    explicit chroTimer(const std::string& tag) : from_(std::chrono::steady_clock::now()), tag_(tag) {
    }
    explicit chroTimer(std::string&& tag) : from_(std::chrono::steady_clock::now()), tag_(std::move(tag)) {
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


int main() {
    uint8_t buffer[65536];
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    chroTimer timer{"timer"};
    timer.set_tag(name);
    while (true) {
        if(timer.duration() < 1 ) {
            continue;
        }
        timer.reset();

        ssize_t len = recv(fd, buffer, sizeof(buffer), 0);
        if (len < 0) {
            perror("recv");
            break;
        }

        if (len < static_cast<ssize_t>(sizeof(ethhdr) + sizeof(iphdr))) {
            continue;
        }

        const ethhdr* eth = reinterpret_cast<const ethhdr*>(buffer);
        if (ntohs(eth->h_proto) != ETH_P_IP) {
            continue;
        }

        const iphdr* ip = reinterpret_cast<const iphdr*>(buffer + sizeof(ethhdr));

        char src[INET_ADDRSTRLEN] = {};
        char dst[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
        inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));

        // 7. 출력 (protocol: 1=ICMP, 6=TCP, 17=UDP)
        printf("[%f] %s -> %s  proto=%u  %u bytes\n",
            timer.duration(),
            src, dst,
            static_cast<unsigned int>(ip->protocol),
            static_cast<unsigned int>(ntohs(ip->tot_len)));
    }

    close(fd);
    return 0;
}