# PROTECT_RASPI

라즈베리파이 NAS를 외부에 열어 두었을 때 들어오는 공격(포트 스캔, 연속 접속 시도)을 raw 소켓으로 감지하고 nftables로 차단하는 데몬 `guard`.

## 디렉터리 구조

패킷이 흐르는 순서대로 계층을 나눴다. 의존은 `ep`에서 바깥으로만 향하고, 아래 계층은 위 계층을 모른다.

```
ep ──→ scnet ──→ packet
 ├───→ detect ──→ packet
 ├───→ block
 └───→ store
```

| 디렉터리 | 네임스페이스 | 역할 | 상태 |
|---|---|---|---|
| `ep/` | `RS::ep` | epoll 이벤트 루프와 핸들러. `rawsockHandler`가 아래 계층들을 받아 수신 → 판정 → 차단 → 기록 순서로 호출한다. 타이머, 시그널도 핸들러로 붙는다. | 구현됨 |
| `scnet/` | `RS::scnet` | 수신·해석. `rawsock`이 AF_PACKET 소켓으로 프레임을 받고, `parser`가 이더넷·IP·L4 헤더를 검증해 `packet` 객체로 만든다. 무엇을 감지할지는 모른다. | 구현됨 |
| `packet/` | `RS::packet` | 해석된 패킷 타입. `ip_RS`와 하위 `ip_TCP_RS`, `ip_UDP_RS`, `ip_ICMP_RS`. 다른 디렉터리에 의존하지 않는다. | 구현됨 |
| `detect/` | `RS::detect` | 판정. `analyzer`가 감지기들을 소유하고 패킷 종류별로 분배한다. 감지기는 출발지 IP별 슬라이딩 윈도우 기록을 들고 임계치를 넘는지 본다. 임계치·창은 `config.h`. | `rate_detector` 구현됨, `port_scan_detector` 예정 |
| `block/` | `RS::block` | 차단. `whitelist`는 감지·차단 제외 대상(단일 IP, 대역). `blocker`가 nftables set에 IP를 timeout과 함께 넣고, 메모리에 차단 목록을 유지한다. | `whitelist` 구현됨, `blocker` 예정 |
| `store/` | `RS::store` | 기록. 감지·차단 이력과 LAN 장비 목록을 SQLite에 저장한다. | 예정 |
| `util/` | `RS::util` | 공용 도구. 타임스탬프 로거. | 구현됨 |
| `expr/` | — | 단계별 실험 코드. 빌드에 포함되지 않으며 각 파일 상단의 `g++` 명령으로 따로 빌드한다. | — |

`include/`와 `src/`는 같은 하위 구조를 가진다. 헤더는 `include/` 기준 경로로 포함한다 (`#include "ep/epoll_RS.h"`).

## 패킷 하나의 흐름

```
rawsockHandler::on_readable()
  1. scnet::rawsock_recv()        프레임 수신 → parser → packet::ip_RS
  2. whitelist / 이미 차단된 IP   → 스킵
  3. detect                       프로토콜별 조건에 맞는 패킷만 감지기에 전달
       TCP  : ACK 비트 없는 패킷 (SYN, 스텔스 스캔)
       UDP  : 목적지 포트 < 32768 (내 질의의 응답 제외)
       ICMP : echo request
  4. 임계치 초과 → block           nft blocklist 추가 (timeout 후 자동 해제)
  5. store                        감지·차단 이력 기록
```

## 빌드 / 실행

```sh
make              # 릴리스 빌드 -> build/release/guard
make DEBUG=1      # 디버그 빌드 -> build/debug/guard (ASan/UBSan)
make run          # 빌드 후 sudo로 실행
make clean
```

raw 소켓과 nftables를 쓰므로 root 권한이 필요하다. 링크 라이브러리: `-lsqlite3`.

## 목표 기능

1. 포트 스캔 차단
2. 연속 TCP 요청 차단 (화이트리스트 제외)
3. 새 장비 감지 및 장비 관제
4. (선택) 같은 IP의 MAC이 바뀌면 ARP 스푸핑 경고
