#!/bin/bash

set -e

BIN=./ipk-L2L3-scan
IFACE=br0

fail=0

echo "===== CLEANUP (PREVIOUS RUN) ====="
for i in {1..10}; do
    sudo ip netns del ns$i 2>/dev/null || true
done
sudo ip link del br0 2>/dev/null || true

echo "===== SETUP NETWORK ====="

# bridge
sudo ip link add name br0 type bridge
sudo ip link set br0 up

# IPv6 + IPv4 for root
sudo ip addr add fd00::1/120 dev br0
sudo ip addr add 192.168.100.1/24 dev br0

# create 10 hosts
for i in {1..10}; do
    sudo ip netns add ns$i

    sudo ip link add veth$i type veth peer name veth${i}br

    sudo ip link set veth$i netns ns$i
    sudo ip link set veth${i}br master br0

    sudo ip link set veth${i}br up
    sudo ip netns exec ns$i ip link set veth$i up

    # IPv6
    sudo ip netns exec ns$i ip addr add fd00::$(($i+1))/120 dev veth$i

    # IPv4
    sudo ip netns exec ns$i ip addr add 192.168.100.$(($i+1))/24 dev veth$i
done

sleep 1

echo "===== TEST A: ARGUMENT PARSING ====="

echo "A1: help"
$BIN -h | grep -q "Usage" || fail=1

echo "A2: no args"
if $BIN >/dev/null 2>&1; then fail=1; fi

echo "A3: interface list"
$BIN -i >/dev/null || fail=1

echo "A4: invalid interface"
if $BIN -i fake0 -s fd00::/120 >/dev/null 2>&1; then fail=1; fi

echo "A5: invalid subnet"
if $BIN -i $IFACE -s fd00:: >/dev/null 2>&1; then fail=1; fi

echo "===== TEST B: OUTPUT FORMAT ====="

OUT=$(sudo $BIN -i $IFACE -s fd00::2/128)

echo "$OUT" | grep -q "Scanning ranges:" || fail=1
echo "$OUT" | grep -q "^$" || fail=1

echo "===== TEST C: IPv4 (ARP + ICMPv4) ====="

echo "C1: single host"
OUT=$(sudo $BIN -i $IFACE -s 192.168.100.2/32)

echo "$OUT" | grep -q "arp OK" || fail=1
echo "$OUT" | grep -q "icmpv4 OK" || fail=1

echo "C2: multi host"
OUT=$(sudo $BIN -i $IFACE -s 192.168.100.0/24)

echo "$OUT" | grep -q "arp OK" || fail=1
COUNT=$(echo "$OUT" | grep -c "arp OK")
if [ "$COUNT" -lt 5 ]; then fail=1; fi

echo "C3: timeout"
OUT=$(sudo $BIN -i $IFACE -w 1 -s 192.168.100.0/24)

echo "$OUT" | grep -q "FAIL" || fail=1

echo "===== TEST D: IPv6 (NDP + ICMPv6) ====="

echo "D1: single host"
OUT=$(sudo $BIN -i $IFACE -s fd00::2/128)

echo "$OUT" | grep -q "ndp OK" || fail=1
echo "$OUT" | grep -q "icmpv6 OK" || fail=1

echo "D2: multi host"
OUT=$(sudo $BIN -i $IFACE -s fd00::/120)

echo "$OUT" | grep -q "ndp OK" || fail=1
COUNT=$(echo "$OUT" | grep -c "ndp OK")
if [ "$COUNT" -lt 5 ]; then fail=1; fi

echo "D3: timeout"
OUT=$(sudo $BIN -i $IFACE -w 1 -s fd00::/120)

echo "$OUT" | grep -q "FAIL" || fail=1

echo "===== CLEANUP ====="

for i in {1..10}; do
    sudo ip netns del ns$i 2>/dev/null || true
done
sudo ip link del br0 2>/dev/null || true

echo "===== RESULT ====="

if [ $fail -eq 0 ]; then
    echo "ALL TESTS PASSED"
    exit 0
else
    echo "TESTS FAILED"
    exit 1
fi
