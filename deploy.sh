#!/bin/sh
# guard 빌드 결과를 서비스 디렉터리로 복사 => 서비스를 (재)시작함
#   ./deploy.sh : 빌드 + 복사 + DB 디렉터리 권한 + 재시작
#   ./deploy.sh install : 처음 한 번, 유닛 파일 등록 + enable + 배포
# 권한 구조: 실행 파일과 logs/는 root 소유. DB는 data/ 아래에 두고 그룹 guard가 읽고 쓴다
# (웹 콘솔 guard_web이 전용 계정 guardweb, 그룹 guard로 돌면서 같은 DB를 씀. ../NAS_GUARD_WEB/deploy.sh)
set -e
cd "$(dirname "$0")"
SV=/home/raspi/sv/guard   # 서비스 경로
DATA=$SV/data             # DB 디렉터리. root:guard 2770, 파일 660
WHAT=${1:-deploy}

setup_data() {
    # WAL 모드는 마지막 연결이 닫힐 때 -wal, -shm을 지우고 다음에 다시 만들므로 디렉터리에 그룹 쓰기가 필요하다
    sudo groupadd -f guard
    sudo mkdir -p $DATA
    sudo chown root:guard $DATA
    sudo chmod 2770 $DATA	# setgid: 안에 만들어지는 파일의 그룹이 guard
    # DB는 처음에만 만든다. 개발 DB가 있으면 복사, 없으면 빈 파일 (SQLite는 0바이트 파일을 빈 DB로 보고 guard가 테이블을 만듦).
    # SQLite가 새로 만드는 파일은 644라(umask로는 그룹 쓰기를 못 더함) 여기서 660으로 미리 만들어 둔다. -wal, -shm은 이 파일의 모드를 따라간다
    # data/는 2770이라 raspi 셸에서는 안이 안 보인다. 검사와 글롭은 sudo 안에서 한다
    if ! sudo test -f $DATA/guard.db; then
        if [ -f guard.db ]; then
            sudo install -m 660 -o root -g guard guard.db $DATA/guard.db
        else
            sudo install -m 660 -o root -g guard /dev/null $DATA/guard.db
        fi
    fi
    sudo sh -c "chown root:guard $DATA/guard.db* && chmod 660 $DATA/guard.db*"	# 배포할 때마다 맞춰 둔다
}

deploy_guard() {
    make
    sudo mkdir -p $SV/logs
    sudo cp build/release/guard $SV/guard.new
    sudo mv $SV/guard.new $SV/guard	# 실행 중인 바이너리를 덮어쓰지 않고 교체
    setup_data
    sudo systemctl restart guard
    echo "guard: $(systemctl is-active guard)"
}

install_unit() {
    sudo mkdir -p $SV
    sudo cp deploy/guard.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable guard
}

case "$WHAT" in
    deploy) deploy_guard ;;
    install) install_unit; deploy_guard ;;
    *) echo "usage: $0 [deploy|install]"; exit 1 ;;
esac
