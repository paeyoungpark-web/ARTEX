#!/bin/bash
# U-07: /etc/passwd 파일 소유자 및 권한
echo "=== U-07 CHECK START ==="
ls -la /etc/passwd
OWNER=$(stat -c '%U' /etc/passwd 2>/dev/null || stat -f '%Su' /etc/passwd 2>/dev/null)
PERM=$(stat -c '%a' /etc/passwd 2>/dev/null || stat -f '%Lp' /etc/passwd 2>/dev/null)
echo "OWNER=$OWNER"
echo "PERM=$PERM"
echo "=== U-07 CHECK END ==="
