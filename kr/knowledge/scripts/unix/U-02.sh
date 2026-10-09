#!/bin/bash
# U-02: 패스워드 복잡성 설정
echo "=== U-02 CHECK START ==="
echo "[CHECK] pwquality.conf"
if [ -f /etc/security/pwquality.conf ]; then
    grep -E "^(minlen|dcredit|ucredit|lcredit|ocredit)" /etc/security/pwquality.conf 2>/dev/null
else
    echo "PWQUALITY_NOT_FOUND"
fi

echo "[CHECK] pam system-auth"
if [ -f /etc/pam.d/system-auth ]; then
    grep -i "pam_pwquality\|pam_cracklib" /etc/pam.d/system-auth 2>/dev/null || echo "NO_PW_MODULE"
else
    echo "SYSTEM_AUTH_NOT_FOUND"
fi

echo "[CHECK] login.defs"
grep -E "^PASS_MIN_LEN" /etc/login.defs 2>/dev/null || echo "PASS_MIN_LEN_NOT_SET"
echo "=== U-02 CHECK END ==="
