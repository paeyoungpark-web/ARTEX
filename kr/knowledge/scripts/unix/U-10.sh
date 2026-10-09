#!/bin/bash
# U-10: /etc/(x)inetd.conf 소유자 및 권한
echo "=== U-10 CHECK START ==="
for f in /etc/inetd.conf /etc/xinetd.conf; do
    if [ -f "$f" ]; then
        echo "[FILE] $f"
        ls -la "$f"
        OWNER=$(stat -c '%U' "$f" 2>/dev/null || stat -f '%Su' "$f" 2>/dev/null)
        PERM=$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f" 2>/dev/null)
        echo "OWNER=$OWNER"
        echo "PERM=$PERM"
    fi
done
if [ ! -f /etc/inetd.conf ] && [ ! -f /etc/xinetd.conf ]; then
    echo "INETD_NOT_FOUND"
fi
echo "=== U-10 CHECK END ==="
