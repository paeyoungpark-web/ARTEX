#!/bin/bash
# U-04: 패스워드 파일 보호
echo "=== U-04 CHECK START ==="
echo "[CHECK] shadow file exists"
ls -la /etc/shadow 2>/dev/null || echo "SHADOW_NOT_FOUND"

echo "[CHECK] passwd second field"
# 두 번째 필드가 x가 아닌 계정 확인 (shadow 미사용 = 취약)
awk -F: '$2 != "x" && $2 != "!!" && $2 != "*" && $2 != "!" {print $1":"$2}' /etc/passwd 2>/dev/null
PASSWD_EXPOSED_COUNT=$(awk -F: '$2 != "x" && $2 != "!!" && $2 != "*" && $2 != "!" {count++} END {print count+0}' /etc/passwd 2>/dev/null)
echo "EXPOSED_COUNT=$PASSWD_EXPOSED_COUNT"
echo "=== U-04 CHECK END ==="
