# DB 쿼리 모음

guard가 쓰는 SQLite 파일(`guard.db`)에 자주 날리는 쿼리. 경로는 환경변수 `GUARD_DB_PATH`, 없으면 실행 디렉터리의 `guard.db`.

- 서비스(systemd `guard`): `/home/raspi/sv/guard/guard.db` (유닛 파일이 `GUARD_DB_PATH`로 지정). 웹 콘솔(`guard_web`)도 `sv/guard_web/config.ini`로 같은 파일을 본다.
- 개발 중 `make run`: 저장소 루트의 `guard.db`.

파일은 root 소유라 `sudo`가 필요하다. WAL 모드라 guard가 돌고 있는 동안에도 읽고 쓸 수 있다. 아래 예시는 서비스 DB 기준이며 `DB` 변수를 먼저 잡아 두면 편하다.

```sh
DB=/home/raspi/sv/guard/guard.db
```

설정과 화이트리스트를 바꾼 뒤에는 HUP를 보내야 반영된다. `nft_*`와 `log_path`는 HUP로 안 바뀌고 재시작이 필요하다. 가장 쉬운 방법은 웹 콘솔(저장하면 HUP까지 보냄)이고, 직접 고쳤을 때는 아래 중 하나.

```sh
sudo systemctl reload guard          # 서비스일 때 (ExecReload가 SIGHUP)
sudo kill -HUP $(pgrep -x guard)     # make run 등 직접 띄웠을 때
```

## 접속

```sh
sudo sqlite3 $DB "SELECT * FROM tbl_config_info;"   # 한 줄
sudo sqlite3 -header -column $DB "SELECT * FROM tbl_whitelist;"

sudo sqlite3 $DB           # 대화형
.tables                    # 테이블 목록
.schema tbl_config_info    # 컬럼 보기
.headers on
.mode column
.quit
```

테이블은 guard가 만드는 것(`tbl_config_info`, `tbl_whitelist`, `tbl_device`, `tbl_device_event`, `tbl_block`)과 웹 콘솔이 만드는 것(`tbl_user`, `tbl_web_config`)으로 나뉜다. DB 파일을 지우면 다음 시작 때 guard가 자기 테이블을 기본값으로 다시 만들고, 웹도 자기 테이블을 다시 만든다.

## tbl_config_info (설정, 행은 id=1 하나)

| 컬럼 | 뜻 | 기본값 |
|---|---|---|
| scan_window_s, scan_threshold | 포트 스캔: N초 안에 서로 다른 포트 N개 (감지기는 아직 미구현, 컬럼만 있음) | 3, 15 |
| tcp_rate_window_s, tcp_rate_threshold | TCP 연속 요청: N초 안에 ACK 없는 패킷 N개 | 3, 15 |
| icmp_rate_window_s, icmp_rate_threshold | ICMP: N초 안에 echo request N개 | 10, 100 |
| max_horizen | IP당 보관 이벤트 상한 | 500 |
| block_timeout_s | 차단 유지 시간 | 10 |
| nft_family, nft_table, nft_set, nft_chain, nft_priority | nft 객체 이름 (재시작 필요) | inet, guard, blocklist, input, -10 |
| loop_timeout_ms | epoll_wait 최대 대기 | 1000 |
| expire_interval_s | 만료 정리 타이머 주기 | 1 |
| mem_log_every_ticks | 메모리 로그와 장비 last_seen 반영 주기 (틱 수. 틱이 1초면 60은 1분) | 60 |
| log_path | 로그 파일 (재시작 필요). 상대 경로는 실행 디렉터리 기준. 실제 파일은 날짜가 붙은 이름 (`logs/guard.2026-10-23.log`), 날이 바뀌면 새 파일 | logs/guard.log |
| log_keep_days | 날짜별 로그 파일 보관 일수. 오늘 기준 이보다 오래된 파일은 guard가 지운다. 0이면 안 지움 | 7 |
| device_expire_s | 이 시간 동안 안 보인 장비는 목록에서 삭제. 0이면 안 지움 | 0 |
| arp_spoof_window_s, arp_spoof_threshold | 같은 IP의 MAC이 N초 안에 N번 바뀌면 스푸핑 의심 | 60, 3 |
| updated_at | 행이 생긴 시각 (유닉스 초). guard는 읽지 않음 | 생성 시각 |

기본값은 `include/settings.h`에 있다. 나중에 추가된 컬럼(`device_expire_s`, `arp_spoof_*`, `log_keep_days`)은 기존 DB에 `ALTER TABLE`로 붙는데, 예전 버전으로 만든 DB는 `.schema`에 `device_expire_s DEFAULT 604800`으로 보일 수 있다. 실제 동작은 행에 든 값만 보므로 값이 0이면 안 지운다.

```sql
-- 현재 값
SELECT * FROM tbl_config_info;

-- 임계치 올리기 (운영용)
UPDATE tbl_config_info SET tcp_rate_window_s=30, tcp_rate_threshold=50 WHERE id=1;
UPDATE tbl_config_info SET scan_window_s=3, scan_threshold=15 WHERE id=1;
UPDATE tbl_config_info SET icmp_rate_window_s=10, icmp_rate_threshold=100 WHERE id=1;

-- 차단 시간 10분
UPDATE tbl_config_info SET block_timeout_s=600 WHERE id=1;

-- 안 보인 지 7일 지난 장비는 목록에서 삭제
UPDATE tbl_config_info SET device_expire_s=604800 WHERE id=1;

-- 로그 파일 30일 보관 (HUP로 바로 반영. 다음 날짜 변경 때 정리)
UPDATE tbl_config_info SET log_keep_days=30 WHERE id=1;

-- 로그 경로 절대 경로로 (재시작 필요)
UPDATE tbl_config_info SET log_path='/home/raspi/sv/guard/logs/guard.log' WHERE id=1;

-- 테스트용 낮은 값으로 되돌리기
UPDATE tbl_config_info SET tcp_rate_window_s=3, tcp_rate_threshold=15, block_timeout_s=10 WHERE id=1;

-- 행을 지우면 다음 시작 때 settings.h 기본값으로 다시 생긴다
DELETE FROM tbl_config_info;
```

## tbl_whitelist (감지, 차단 제외 IP)

`whitelist.local.h`의 항목에 더해서 적용된다. local 항목은 DB에 없다.
mask가 NULL이면 단일 IP, 있으면 (network, mask) 대역.

```sql
-- 목록
SELECT id, ip, mask, note, datetime(created_at, 'unixepoch', 'localtime') AS created FROM tbl_whitelist;

-- 대역 추가
INSERT INTO tbl_whitelist(ip, mask, note) VALUES ('192.168.0.0', '255.255.255.0', 'lan');

-- 단일 IP 추가
INSERT INTO tbl_whitelist(ip, note) VALUES ('203.0.113.10', 'office');

-- 삭제
DELETE FROM tbl_whitelist WHERE ip = '203.0.113.10';
DELETE FROM tbl_whitelist WHERE id = 3;
```

잘못된 IP 문자열이 들어 있으면 시작 때는 exit 1로 멈추고, HUP 리로드 때는 기존 목록을 유지한다 (로그에 `bad ip`). 외부 접속용 IP가 빠지면 원격 접속이 끊기니 집 LAN에서 먼저 확인한다.

## tbl_device (LAN 장비 목록)

MAC이 기본키. guard가 새로 보이면 바로 INSERT하고, last_seen과 ip 변경은 `mem_log_every_ticks` 주기(기본 1분)로 모아서 UPDATE한다. `device_expire_s`가 0보다 크면 그 시간 동안 안 보인 장비를 DELETE (기본 0, 안 지움).
`name`, `note`는 사람이 채우는 칸이다 (guard는 건드리지 않음). 웹 콘솔 장비 화면에서도 고칠 수 있다.

```sql
-- 목록 (최근 본 순)
SELECT mac, ip, name, datetime(first_seen,'unixepoch','localtime') AS first_seen,
       datetime(last_seen,'unixepoch','localtime') AS last_seen
FROM tbl_device ORDER BY last_seen DESC;

-- 이름 없는 장비 (모르는 장비)
SELECT mac, ip, datetime(first_seen,'unixepoch','localtime') AS first_seen FROM tbl_device WHERE name IS NULL;

-- 이름 붙이기
UPDATE tbl_device SET name='공유기', note='ipTIME' WHERE mac='aa:bb:cc:dd:ee:ff';

-- 장비 지우기 (다시 보이면 새 장비로 다시 들어온다)
DELETE FROM tbl_device WHERE mac='aa:bb:cc:dd:ee:ff';
```

## tbl_device_event (장비 이벤트, 알람 기록)

type: `new_device`(새 MAC), `device_gone`(만료 삭제), `mac_changed`(알던 IP의 MAC이 바뀜, 한 번이면 DHCP 재배정일 수 있음), `arp_spoof`(짧은 시간에 여러 번 바뀜, 로그에는 `[ALARM]`). 스푸핑 알람은 window당 한 번만 기록하고 차단은 하지 않는다.

```sql
-- 최근 이벤트
SELECT datetime(time,'unixepoch','localtime') AS t, type, ip, old_mac, new_mac
FROM tbl_device_event ORDER BY id DESC LIMIT 50;

-- 스푸핑 알람만
SELECT datetime(time,'unixepoch','localtime') AS t, ip, old_mac, new_mac FROM tbl_device_event WHERE type='arp_spoof' ORDER BY id DESC;

-- 오래된 이벤트 정리 (30일 이전)
DELETE FROM tbl_device_event WHERE time < strftime('%s','now') - 30*86400;
```

## tbl_block (차단 기록)

차단할 때마다 한 행. reason은 `tcp_syn_flood`, `icmp_flood`, `port_scan`(감지기 미구현이라 아직 안 나옴).

```sql
SELECT datetime(time,'unixepoch','localtime') AS t, ip, reason FROM tbl_block ORDER BY id DESC LIMIT 50;
SELECT ip, COUNT(*) AS n FROM tbl_block GROUP BY ip ORDER BY n DESC;        -- IP별 횟수
SELECT reason, COUNT(*) AS n FROM tbl_block GROUP BY reason;                -- 원인별 횟수
DELETE FROM tbl_block WHERE time < strftime('%s','now') - 30*86400;         -- 30일 이전 정리
```

지금 nft에 실제로 막혀 있는 IP는 DB가 아니라 커널 set에서 본다.

```sh
sudo nft list set inet guard blocklist
```

## tbl_user, tbl_web_config (웹 콘솔 전용)

guard는 읽지 않는다. 웹 콘솔이 시작할 때 없으면 만든다.

- `tbl_user`: 관리자 계정 하나 (username, pw_hash, salt). 비밀번호는 PBKDF2-SHA256. 행이 없으면 웹이 시작할 때 초기 계정을 넣는다 (값은 `NAS_GUARD_WEB/app/auth.py`).
- `tbl_web_config`: key, value. 지금은 `session_secret`(세션 쿠키 서명 키) 하나. 웹이 처음 뜰 때 만들어 두어 재시작해도 로그인이 유지된다.

```sql
-- 계정 보기
SELECT username, datetime(updated_at,'unixepoch','localtime') AS pw_changed FROM tbl_user;

-- 비밀번호를 잊었을 때: 계정을 지우고 웹을 재시작하면 초기 계정으로 다시 생긴다 (auth.py)
DELETE FROM tbl_user;

-- 모든 로그인 세션 강제 종료: 서명 키를 지우고 웹을 재시작하면 새 키가 생겨 기존 쿠키가 무효가 된다
DELETE FROM tbl_web_config WHERE key='session_secret';
```

```sh
sudo systemctl restart guard_web
```

## 셸 한 줄 예시

```sh
DB=/home/raspi/sv/guard/guard.db

# 임계치 바꾸고 바로 반영
sudo sqlite3 $DB "UPDATE tbl_config_info SET tcp_rate_threshold=50 WHERE id=1;" && sudo systemctl reload guard

# 화이트리스트 추가하고 반영
sudo sqlite3 $DB "INSERT INTO tbl_whitelist(ip,mask,note) VALUES('192.168.0.0','255.255.255.0','lan');" && sudo systemctl reload guard

# 백업 (WAL이라 파일 복사 대신 .backup을 쓴다)
sudo sqlite3 $DB ".backup /home/raspi/guard.backup.db"

# 리로드가 잘 됐는지
journalctl -u guard -n 5 | grep reload
```

## 장비 감지 테스트 (attacker netns)

```sh
sudo ip netns exec attacker ip neigh flush all && sudo ip netns exec attacker ping -c1 10.99.0.1   # ARP -> [device] new
# MAC을 바꿔 가며 반복하면 mac_changed 두 번 뒤 [ALARM] arp spoof
sudo ip netns exec attacker ip link set dev veth-att down
sudo ip netns exec attacker ip link set dev veth-att address 02:11:11:11:11:11
sudo ip netns exec attacker ip link set dev veth-att up
```
