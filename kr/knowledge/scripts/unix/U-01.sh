#!/bin/bash
# U-01: root 계정 원격접속 제한
# read-only 수집 스크립트 (시스템 변경 없음)
echo "=== U-01 CHECK START ==="
echo "[CHECK] SSH PermitRootLogin"
if [ -f /etc/ssh/sshd_config ]; then
    grep -i "^[[:space:]]*PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null || echo "PermitRootLogin_NOT_SET"
else
    echo "SSHD_CONFIG_NOT_FOUND"
fi

echo "[CHECK] Telnet Service"
systemctl is-active telnet.socket 2>/dev/null || echo "TELNET_INACTIVE"

echo "[CHECK] securetty"
if [ -f /etc/securetty ]; then
    grep -c "pts/" /etc/securetty 2>/dev/null || echo "NO_PTS_IN_SECURETTY"
else
    echo "SECURETTY_NOT_FOUND"
fi
echo "=== U-01 CHECK END ==="
