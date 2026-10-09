#!/bin/bash
# U-03: 계정 잠금 임계값 설정
echo "=== U-03 CHECK START ==="
echo "[CHECK] pam_faillock (RHEL8+)"
for f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    if [ -f "$f" ]; then
        echo "[FILE] $f"
        grep -i "pam_faillock\|pam_tally2" "$f" 2>/dev/null || echo "NO_LOCK_MODULE"
    fi
done

echo "[CHECK] faillock.conf"
if [ -f /etc/security/faillock.conf ]; then
    grep -E "^(deny|unlock_time)" /etc/security/faillock.conf 2>/dev/null
else
    echo "FAILLOCK_CONF_NOT_FOUND"
fi
echo "=== U-03 CHECK END ==="
