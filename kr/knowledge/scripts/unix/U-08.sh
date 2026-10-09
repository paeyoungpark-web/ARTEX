#!/bin/bash
# U-08: /etc/shadow 파일 소유자 및 권한
echo "=== U-08 CHECK START ==="
if [ -f /etc/shadow ]; then
    ls -la /etc/shadow
    OWNER=$(stat -c '%U' /etc/shadow 2>/dev/null || stat -f '%Su' /etc/shadow 2>/dev/null)
    PERM=$(stat -c '%a' /etc/shadow 2>/dev/null || stat -f '%Lp' /etc/shadow 2>/dev/null)
    echo "OWNER=$OWNER"
    echo "PERM=$PERM"
else
    echo "SHADOW_NOT_FOUND"
fi
echo "=== U-08 CHECK END ==="
