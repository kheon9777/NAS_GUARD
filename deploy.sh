#!/bin/sh
# guard 빌드 결과를 서비스 디렉터리로 복사 => 서비스를 (재)시작함
#   ./deploy.sh : 빌드 + 복사 + 재시작
#   ./deploy.sh install : 처음 한 번, 유닛 파일 등록 + enable + 배포
set -e
cd "$(dirname "$0")"
SV=/home/raspi/sv/guard   # 서비스 경로
WHAT=${1:-deploy}

deploy_guard() {
    make
    sudo mkdir -p $SV/logs
    sudo cp build/release/guard $SV/guard.new
    sudo mv $SV/guard.new $SV/guard	# 실행 중인 바이너리를 덮어쓰지 않고 교체
    [ -f $SV/guard.db ] || sudo cp guard.db $SV/guard.db 2>/dev/null || true	# DB는 처음에만 복사
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
