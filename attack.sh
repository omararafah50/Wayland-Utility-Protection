#!/usr/bin/env bash

TARGET_PID=$1

if [ -z "$TARGET_PID" ]; then
    echo "Usage: ./attack.sh <PID>"
    exit 1
fi

echo "=== Attempting Attack on PID: $TARGET_PID ==="

# 1. Attempt gcore / ptrace dump
echo "[1] Testing ptrace attachment via gcore..."
gcore -o dump_$TARGET_PID $TARGET_PID 2>&1
GCORE_EXIT=$?

if [ $GCORE_EXIT -eq 0 ]; then
    echo "[+] gcore dump SUCCESSFUL!"
    
    # Search for magic byte sequence: DE AD BE EF 01 02 03 04
    MATCHES=$(xxd -p dump_$TARGET_PID.* | grep -i "deadbeef01020304" | wc -l)
    echo "[+] Target pattern occurrences found in RAM dump: $MATCHES"
    rm -f dump_$TARGET_PID.*
else
    echo "[-] gcore dump FAILED (Kernel Blocked ptrace)"
fi

# 2. Attempt direct /proc/$PID/mem dump
echo -e "\n[2] Testing direct /proc/$PID/mem read..."
python3 -c "
import sys
try:
    with open('/proc/$TARGET_PID/mem', 'rb') as f:
        f.seek(0)
        print('[+] /proc/mem read SUCCESSFUL!')
except Exception as e:
    print(f'[-] /proc/mem read FAILED: {e}')
"
