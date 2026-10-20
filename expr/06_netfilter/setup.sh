#!/bin/sh
# 포트 스캔 차단용 nftables 설정

nft add table inet guard
nft add set inet guard blocklist '{ type ipv4_addr; flags timeout; }'
nft add chain inet guard input '{ type filter hook input priority -10; policy accept; }'
nft add rule inet guard input ip saddr @blocklist tcp dport 22 accept
nft add rule inet guard input ip saddr @blocklist drop

nft list ruleset