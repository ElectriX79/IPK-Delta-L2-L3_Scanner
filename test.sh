#!/bin/bash

# COLORS
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
NC="\033[0m"

PASS=0
FAIL=0

cd cmak-build-debug

function run_test() {
    NAME=$1
    CMD=$2
    EXPECT=$3

    echo -e "${YELLOW}Running: $NAME${NC}"

    OUTPUT=$(eval $CMD 2>/dev/null)

    if echo "$OUTPUT" | grep -q "$EXPECT"; then
        echo -e "${GREEN}PASS${NC}"
        PASS=$((PASS+1))
    else
        echo -e "${RED}FAIL${NC}"
        echo "Expected: $EXPECT"
        echo "Got:"
        echo "$OUTPUT"
        FAIL=$((FAIL+1))
    fi

    echo "-----------------------------"
}

echo "===== BUILD ====="
make clean && make

if [ $? -ne 0 ]; then
    echo -e "${RED}BUILD FAILED${NC}"
    exit 1
fi

echo -e "${GREEN}BUILD OK${NC}"
echo "============================="

# =============================
# TESTS
# =============================

# 1. Help
run_test "Help flag" "./ipk-L2L3-scan -h" "Scanning ranges"

# 2. Invalid input
run_test "Invalid subnet" "./ipk-L2L3-scan -i lo -s invalid" "Invalid"

# 3. IPv4 parsing
run_test "IPv4 parsing" \
"sudo ./ipk-L2L3-scan -i lo -s 127.0.0.0/30" \
"Scanning ranges"

# 4. IPv6 parsing
run_test "IPv6 parsing" \
"sudo ./ipk-L2L3-scan -i lo -s ::1/128" \
"Scanning ranges"

# 5. ARP basic test (loopback nebude odpovedať → FAIL OK)
run_test "ARP basic" \
"sudo ./ipk-L2L3-scan -i lo -s 127.0.0.0/30" \
"arp"

# 6. ICMP localhost
run_test "ICMP localhost" \
"sudo ./ipk-L2L3-scan -i lo -s 127.0.0.1/32" \
"icmpv4"

# 7. IPv6 ICMP localhost
run_test "ICMPv6 localhost" \
"sudo ./ipk-L2L3-scan -i lo -s ::1/128" \
"icmpv6"

# =============================
# SUMMARY
# =============================

echo ""
echo "===== SUMMARY ====="
echo -e "${GREEN}PASS: $PASS${NC}"
echo -e "${RED}FAIL: $FAIL${NC}"

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED 🎉${NC}"
else
    echo -e "${RED}SOME TESTS FAILED ❌${NC}"
fi
