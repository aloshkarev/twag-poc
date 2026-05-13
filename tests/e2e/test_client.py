import socket
import struct
import time
import sys

RADIUS_PORT = 1812
TWAG_IP = '127.0.0.1'

def send_radius_access_request(sock, mac, req_id, imsi):
    # RADIUS Header: Code(1), Id(1), Length(2), Auth(16)
    code = 1 # Access-Request
    authenticator = b'\x00' * 16
    
    # Attribute 31: Calling-Station-Id (MAC)
    attr_mac = struct.pack('>B B', 31, len(mac) + 2) + mac.encode('ascii')
    
    # EAP-Message (Attribute 79)
    # EAP: Code=2 (Response), Id=req_id, Length(2), Type=1 (Identity), Data(IMSI)
    eap_data = imsi.encode('ascii')
    eap_len = 5 + len(eap_data)
    eap_payload = struct.pack('>B B H B', 2, req_id, eap_len, 1) + eap_data
    
    attr_eap = struct.pack('>B B', 79, len(eap_payload) + 2) + eap_payload
    
    attrs = attr_mac + attr_eap
    length = 20 + len(attrs)
    
    header = struct.pack('>B B H', code, req_id, length) + authenticator
    packet = header + attrs
    
    sock.sendto(packet, (TWAG_IP, RADIUS_PORT))
    
def send_radius_accounting_stop(sock, mac, req_id):
    code = 4 # Accounting-Request
    authenticator = b'\x00' * 16
    
    # Attribute 31: Calling-Station-Id (MAC)
    attr_mac = struct.pack('>B B', 31, len(mac) + 2) + mac.encode('ascii')
    
    # Attribute 4: Acct-Status-Type = 2 (Stop)
    attr_status = struct.pack('>B B I', 4, 6, 2)
    
    attrs = attr_mac + attr_status
    length = 20 + len(attrs)
    
    header = struct.pack('>B B H', code, req_id, length) + authenticator
    packet = header + attrs
    
    sock.sendto(packet, (TWAG_IP, RADIUS_PORT))

def test_congestion_control():
    print("[TestClient] Testing Congestion Control (Rate Limiting)...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    
    # We assume max_active_sessions is set to 5 in the test config.
    # We will send 6 different MACs.
    successes = 0
    rejects = 0
    
    for i in range(1, 7):
        mac = f"AA:BB:CC:DD:EE:0{i}"
        imsi = f"00101012345678{i}"
        send_radius_access_request(sock, mac, i, imsi)
        
        try:
            resp, _ = sock.recvfrom(1024)
            code = resp[0]
            if code == 2: # Access-Accept
                successes += 1
            elif code == 3: # Access-Reject
                rejects += 1
                print(f"[TestClient] Received Access-Reject for MAC {mac} (Congestion Control worked!)")
        except socket.timeout:
            print(f"[TestClient] Timeout waiting for response for MAC {mac}")
            
    print(f"[TestClient] Congestion Control Test: {successes} Accepted, {rejects} Rejected.")
    if rejects == 0:
        print("[TestClient] FAILED: Expected at least one reject!")
        sys.exit(1)

def test_detach():
    print("[TestClient] Testing Detach Flow...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    
    mac = "AA:BB:CC:DD:EE:01"
    send_radius_accounting_stop(sock, mac, 100)
    try:
        resp, _ = sock.recvfrom(1024)
        if resp[0] == 5: # Accounting-Response
            print(f"[TestClient] Received Accounting-Response for MAC {mac} detach.")
    except socket.timeout:
        print("[TestClient] Timeout waiting for Accounting-Response")

def main():
    time.sleep(1)
    test_congestion_control()
    time.sleep(2)
    test_detach()

if __name__ == '__main__':
    main()