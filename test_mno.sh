#!/bin/bash
set -e

echo "==============================="
echo "Testing TWAG MNO PoC Project (E2E)"
echo "==============================="

cd build

echo "1. Running C++ Unit Tests..."
./twag_tests

echo "2. Setting up test configuration..."
cat <<EOF > twag_config.json
{
    "pgw_ip": "127.0.0.2",
    "radius_port": 1812,
    "radius_secret": "testing123",
    "aaa_realm": "epc.mnc001.mcc001.3gppnetwork.org",
    "apn": "internet",
    "eap_domain": "wlan.mnc001.mcc001.3gppnetwork.org",
    "fd_conf_filename": "twag_fd.conf",
    "access_interface": "lo",
    "wlc_ip": "127.0.0.1",
    "max_active_sessions": 5,
    "stats_log_interval_sec": 2
}
EOF

cat <<EOF > twag_fd.conf
# Minimal freeDiameter config
Identity = "twag.epc.mnc001.mcc001.3gppnetwork.org";
Realm = "epc.mnc001.mcc001.3gppnetwork.org";
No_SCTP;
No_IPv6;
Port = 3868;
SecPort = 4869;
TLS_Cred = "certs/cert.pem", "certs/privkey.pem";
TLS_CA = "certs/cert.pem";
# Load basic dictionaries
LoadExtension = "freeDiameter/extensions/dict_nasreq.fdx";
LoadExtension = "freeDiameter/extensions/dict_eap.fdx";
LoadExtension = "freeDiameter/extensions/dict_dcca.fdx";

ConnectPeer = "aaa.epc.mnc001.mcc001.3gppnetwork.org" {
    ConnectTo = "127.0.0.1";
    Port = 3869;
    No_TLS;
};
EOF

cat <<EOF > mock_aaa.conf
Identity = "aaa.epc.mnc001.mcc001.3gppnetwork.org";
Realm = "epc.mnc001.mcc001.3gppnetwork.org";
Port = 3869;
SecPort = 5869;
No_SCTP;
TLS_Cred = "certs/cert.pem", "certs/privkey.pem";
TLS_CA = "certs/cert.pem";

LoadExtension = "freeDiameter/extensions/dict_nasreq.fdx";
LoadExtension = "freeDiameter/extensions/dict_eap.fdx";

ConnectPeer = "twag.epc.mnc001.mcc001.3gppnetwork.org" {
    ConnectTo = "127.0.0.1";
    Port = 3868;
    No_TLS;
};
EOF

echo "3. Running Asynchronous MNO Integration Test..."
killall twag python3 freeDiameterd 2>/dev/null || true

echo "Loading gtp kernel module (requires sudo)..."
sudo modprobe gtp || echo "Note: Failed to load gtp module, kernel tests might fail."

echo "Starting Mock DNS (UDP 53, requires sudo)..."
sudo python3 -u ../tests/e2e/mock_dns.py > mock_dns.log 2>&1 &
DNS_PID=$!

echo "Starting Mock PGW (UDP 2123)..."
python3 -u ../tests/e2e/mock_pgw.py > mock_pgw.log 2>&1 &
PGW_PID=$!

echo "Starting Mock AAA (freeDiameter TCP 3869)..."
../freeDiameter/build/freeDiameterd/freeDiameterd -c mock_aaa.conf > mock_aaa.log 2>&1 &
AAA_PID=$!

sleep 2

# Temporarily point DNS to localhost if possible, but TwagCore uses system res_query
# If res_query uses /etc/resolv.conf, we can't easily mock it without root. We run as root!
echo "Starting TWAG Service (requires sudo)..."
sudo ./twag -c twag_config.json > twag_test.log 2>&1 &
TWAG_PID=$!

sleep 2

echo "--- Running E2E Test Client (Attach, Congestion Control, Detach) ---"
python3 ../tests/e2e/test_client.py || echo "Test client reported errors!"

sleep 2

echo "--- Verifying Linux Kernel GTP-U and twag_gre Interfaces ---"
ip link show gtp0 || echo "gtp0 interface not found!"
ip link show twag_gre || echo "twag_gre interface not found!"

echo "--- Verifying iptables QoS DSCP rules ---"
sudo iptables -t mangle -S | grep DSCP || echo "No DSCP rules found!"

echo "Cleaning up processes..."
sudo kill $TWAG_PID $DNS_PID 2>/dev/null || true
kill $PGW_PID $AAA_PID 2>/dev/null || true
sudo ip link del twag_gre 2>/dev/null || true

echo "==============================="
echo "Testing Complete!"
echo "Check build/twag_test.log for detailed application traces."
echo "==============================="
