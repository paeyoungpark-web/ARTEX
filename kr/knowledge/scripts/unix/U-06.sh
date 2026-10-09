#!/bin/bash
# U-06: 파일 및 디렉터리 소유자 설정
echo "=== U-06 CHECK START ==="
echo "[CHECK] nouser files"
NOUSER=$(find / -nouser -type f 2>/dev/null | head -20)
NOUSER_COUNT=$(find / -nouser -type f 2>/dev/null | wc -l)
echo "NOUSER_COUNT=$NOUSER_COUNT"
echo "$NOUSER"
echo "[CHECK] nogroup files"
NOGROUP_COUNT=$(find / -nogroup -type f 2>/dev/null | wc -l)
echo "NOGROUP_COUNT=$NOGROUP_COUNT"
echo "=== U-06 CHECK END ==="
