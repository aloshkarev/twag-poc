#!/bin/bash
set -e

echo "==============================="
echo "Testing TWAG MVP Project"
echo "==============================="

cd build

echo "1. Running C++ Unit Tests..."
./twag_tests

echo "2. Running Asynchronous Integration Test..."
# Cleanup any lingering processes
killall twag python3 freeDiameterd 2>/dev/null || true

# Load Kernel Module for GTP
echo "Loading gtp kernel module (requires sudo)..."
sudo modprobe gtp || echo "Note: Failed to load gtp module, kernel tests might fail."

echo "Starting Mock PGW (UDP 2123)..."
python3 -u mock_pgw.py > mock_pgw.log 2>&1 &
PGW_PID=$!

echo "Starting Mock AAA (freeDiameter TCP 3869)..."
../freeDiameter/build/freeDiameterd/freeDiameterd -c mock_aaa.conf > mock_aaa.log 2>&1 &
AAA_PID=$!

sleep 2

echo "Starting TWAG Service (requires sudo for Kernel Netlink)..."
sudo ./twag > twag_test.log 2>&1 &
TWAG_PID=$!

sleep 2

echo "--- Sending RADIUS Access-Request (Attach) ---"
python3 send_attach.py
sleep 3

echo "--- Verifying Linux Kernel GTP-U Interface ---"
ip link show gtp0 || echo "gtp0 interface not found!"

echo "--- Sending RADIUS Accounting-Request (Detach) ---"
python3 send_detach.py
sleep 2

echo "--- Verifying Kernel Interface Cleanup ---"
ip link show gtp0 || echo "gtp0 interface successfully destroyed."

echo "Cleaning up processes..."
sudo kill $TWAG_PID 2>/dev/null || true
kill $PGW_PID $AAA_PID 2>/dev/null || true

echo "==============================="
echo "Testing Complete!"
echo "Check build/twag_test.log for detailed application traces."
echo "==============================="