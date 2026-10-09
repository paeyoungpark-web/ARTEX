#!/bin/bash
# U-09: /etc/hosts 파일 소유자 및 권한
echo "=== U-09 CHECK START ==="
ls -la /etc/hosts
OWNER=$(stat -c '%U' /etc/hosts 2>/dev/null || stat -f '%Su' /etc/hosts 2>/dev/null)
PERM=$(stat -c '%a' /etc/hosts 2>/dev/null || stat -f '%Lp' /etc/hosts 2>/dev/null)
echo "OWNER=$OWNER"
echo "PERM=$PERM"
echo "=== U-09 CHECK END ==="
