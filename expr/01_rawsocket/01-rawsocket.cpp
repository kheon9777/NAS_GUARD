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

#include <cstdint>
#include <cstdio>

int main() {
    // 1. 모든 패킷을 받는 raw 소켓 열기
    // AF_PACKET : 네트워크 층 가장 아래, 랜카드 바로 위에서 패킷을 받겠다.
    // SOCK_RAW : Ethernet 헤더를 포함한 프레임 다 받는다. 
    // 세 번째 인자 : 패킷 거르는 필터링, ETH_P_ALL은 다 받는다는 소리
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    uint8_t buffer[65536];

    while (true) {
        // 2. 패킷 하나 받기
        // fd : 시스템 콜로 요청해서 커널에게 부여받은, I/O자원 접근에 필요한 정수 
        // 커널은 모든 프로세스에 대한 각각의 fd관리 테이블을 저장하고 있음. 시스템콜이 오면 그 프로세스의 fd테이블에서 찾아 어떤 자원인지 식별해서 작업을 수행함
        ssize_t len = recv(fd, buffer, sizeof(buffer), 0);
        if (len < 0) {
            perror("recv");
            break;
        }

        // 3. Ethernet + IP 헤더도 안 되는 짧은 패킷은 건너뛰기
        if (len < static_cast<ssize_t>(sizeof(ethhdr) + sizeof(iphdr))) {
            continue;
        }
        /*
        * recv()로 받은 프레임 구조 (AF_PACKET + SOCK_RAW)
        *
        * 바이트 오프셋
        * 0        6        12     14              14+ihl*4
        * +--------+--------+------+---------------+--------------+--------+------+
        * | 목적지 | 출발지 | 타입 | IP 헤더       | TCP/UDP/ICMP | 데이터 | 패딩 |
        * | MAC 6  | MAC 6  | 2    | 20~60 (ihl*4) | 헤더         |        |      |
        * +--------+--------+------+---------------+--------------+--------+------+
        * |<---- Ethernet 14 ----->|
        *                          |<--------- tot_len (IP 기준) --------->|
        * |<------------------------- len (recv 반환값) ------------------------->|
        */
        printf("-----[ethhdr:%zu iphdr:%zu total:%zd]\n", sizeof(ethhdr), sizeof(iphdr), len);

        // 4. Ethernet 헤더 해석, IPv4만 통과
        const ethhdr* eth = reinterpret_cast<const ethhdr*>(buffer);
        if (ntohs(eth->h_proto) != ETH_P_IP) {
            continue;
        }

        // 5. Ethernet 헤더 바로 뒤가 IP 헤더
        const iphdr* ip = reinterpret_cast<const iphdr*>(buffer + sizeof(ethhdr));

        // 6. IP 주소를 문자열로 변환
        char src[INET_ADDRSTRLEN] = {};
        char dst[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
        inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));

        // 7. 출력 (protocol: 1=ICMP, 6=TCP, 17=UDP)
        printf("%s -> %s  proto=%u  %u bytes\n",
            src, dst,
            static_cast<unsigned int>(ip->protocol),
            static_cast<unsigned int>(ntohs(ip->tot_len)));
    }

    close(fd);
    return 0;
}