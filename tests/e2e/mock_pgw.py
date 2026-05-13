import socket
import struct
import sys

def build_create_session_response(req_data):
    # GTPv2-C Header: Flags(1) = 0x48, Type(1) = 33, Length(2), TEID(4), Seq(3), Spare(1)
    # Parse request to get seq and sender F-TEID if possible. 
    # For PoC, assume TWAG TEID is in the request (usually at offset 8-11 if TEID flag is 1, but CSR usually has TEID=0)
    # Let's extract seq from request
    req_flags = req_data[0]
    if req_flags & 0x08:
        seq = req_data[8:11]
    else:
        seq = req_data[4:7]

    # In CSR, Twag sends its control TEID in F-TEID IE (type 87).
    # We will just broadcast back with TEID=1 or 2, Twag actually looks up by sequence or dest_teid.
    # Wait, Twag expects the TEID in the response header to be its own Control TEID.
    # We'll just search for F-TEID (type 87) in the request to find it.
    twag_c_teid = b'\x00\x00\x00\x01'
    idx = 8 if (req_flags & 0x08) else 8 # wait, if no TEID, header is 8 bytes
    while idx < len(req_data):
        ie_type = req_data[idx]
        ie_len = struct.unpack('>H', req_data[idx+1:idx+3])[0]
        if ie_type == 87: # F-TEID
            twag_c_teid = req_data[idx+5:idx+9]
            break
        idx += 4 + ie_len

    flags = b'\x48'
    msg_type = b'\x21' # 33
    teid = twag_c_teid
    spare = b'\x00'

    # Cause IE (16 = Request Accepted)
    cause_ie = struct.pack('>B H B B', 2, 2, 0, 16) + b'\x00'
    
    # PAA IE (Type 79, len 5, PDN Type 1 (IPv4), IP 10.0.0.5)
    paa_ie = struct.pack('>B H B B', 79, 5, 0, 1) + socket.inet_aton('10.0.0.5')
    
    # Bearer Contexts Created IE (93)
    # Inner IEs: EBI (73, len 1, val 5), Cause (2, len 2, val 16), 
    # F-TEID (87, len 9, v4=1, interface=0, TEID=0x22222222, IP=127.0.0.1)
    # Bearer QoS (80, len 22, qci=5, mbr/gbr=0)
    ebi = struct.pack('>B H B B', 73, 1, 0, 5)
    bcause = struct.pack('>B H B B', 2, 2, 0, 16) + b'\x00'
    bfteid = struct.pack('>B H B B I', 87, 9, 0, 0x80, 0x22222222) + socket.inet_aton('127.0.0.1')
    
    # Bearer QoS: QCI=5
    bqos_data = struct.pack('>B B', 0, 5) + (b'\x00' * 20)
    bqos = struct.pack('>B H B', 80, 22, 0) + bqos_data

    bearer_data = ebi + bcause + bfteid + bqos
    bearer_ie = struct.pack('>B H B', 93, len(bearer_data), 0) + bearer_data

    payload = cause_ie + paa_ie + bearer_ie
    
    msg_len = struct.pack('>H', len(payload) + 8) # 8 bytes for TEID+Seq+Spare
    
    resp = flags + msg_type + msg_len + teid + seq + spare + payload
    print(f"[MockPGW] Sent Create Session Response to TEID {struct.unpack('>I', twag_c_teid)[0]}")
    return resp

def build_delete_session_response(req_data):
    req_flags = req_data[0]
    if req_flags & 0x08:
        seq = req_data[8:11]
        teid = req_data[4:8] # Just echo back the teid or 0
    else:
        seq = req_data[4:7]
        teid = b'\x00\x00\x00\x00'

    flags = b'\x48'
    msg_type = b'\x25' # 37 (Delete Session Response)
    spare = b'\x00'
    
    # Cause IE
    cause_ie = struct.pack('>B H B B', 2, 2, 0, 16) + b'\x00'
    
    msg_len = struct.pack('>H', len(cause_ie) + 8)
    resp = flags + msg_type + msg_len + teid + seq + spare + cause_ie
    print("[MockPGW] Sent Delete Session Response")
    return resp

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(('127.0.0.2', 2123))
    print("[MockPGW] Listening on 127.0.0.2:2123")
    
    while True:
        data, addr = sock.recvfrom(2048)
        if len(data) < 8: continue
        
        msg_type = data[1]
        if msg_type == 32: # Create Session Request
            print("[MockPGW] Received Create Session Request")
            resp = build_create_session_response(data)
            sock.sendto(resp, addr)
        elif msg_type == 36: # Delete Session Request
            print("[MockPGW] Received Delete Session Request")
            resp = build_delete_session_response(data)
            sock.sendto(resp, addr)

if __name__ == '__main__':
    main()