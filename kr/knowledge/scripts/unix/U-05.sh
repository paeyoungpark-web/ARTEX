#!/bin/bash
# U-05: root 홈, 패스 디렉터리 권한 및 패스 설정
echo "=== U-05 CHECK START ==="
echo "[CHECK] root PATH"
echo "ROOT_PATH=$PATH"

echo "[CHECK] dot in PATH"
echo "$PATH" | tr ':' '\n' | grep -n "^\.$" 2>/dev/null
if echo "$PATH" | grep -qE "(^|:)\.(:|$)"; then
    echo "DOT_IN_PATH=YES"
else
    echo "DOT_IN_PATH=NO"
fi

echo "[CHECK] empty element in PATH"
if echo "$PATH" | grep -q "::"; then
    echo "EMPTY_ELEMENT=YES"
else
    echo "EMPTY_ELEMENT=NO"
fi
echo "=== U-05 CHECK END ==="
