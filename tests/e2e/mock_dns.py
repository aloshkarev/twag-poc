import socket
import struct
import sys

def build_dns_response(data):
    # Header: 12 bytes
    txn_id = data[:2]
    flags = b'\x81\x80' # Standard query response, No error
    questions = data[4:6]
    answers = b'\x00\x01' # 1 answer
    auth = b'\x00\x00'
    add = b'\x00\x00'
    
    # Extract query
    idx = 12
    while data[idx] != 0:
        idx += 1
    idx += 1 # null byte
    qtype = struct.unpack('>H', data[idx:idx+2])[0]
    idx += 4 # type + class
    query = data[12:idx]
    
    resp = txn_id + flags + questions + answers + auth + add + query
    
    # Answer pointer to name
    ans_name = b'\xc0\x0c'
    
    if qtype == 35: # NAPTR
        ans_type = struct.pack('>H', 35)
        ans_class = struct.pack('>H', 1)
        ans_ttl = struct.pack('>I', 60)
        
        # RData
        order = struct.pack('>H', 10)
        pref = struct.pack('>H', 10)
        flags_field = b'\x01a'
        services = b'\x14x-3gpp-pgw:x-s2a-gtp'
        regexp = b'\x00'
        replacement = b'\x04mock\x03pgw\x00' # mock.pgw
        
        rdata = order + pref + flags_field + services + regexp + replacement
        ans_datalen = struct.pack('>H', len(rdata))
        
        resp += ans_name + ans_type + ans_class + ans_ttl + ans_datalen + rdata
        print(f"[MockDNS] Sent S-NAPTR response for query")
        return resp
        
    elif qtype == 1: # A
        ans_type = struct.pack('>H', 1)
        ans_class = struct.pack('>H', 1)
        ans_ttl = struct.pack('>I', 60)
        rdata = socket.inet_aton("127.0.0.2")
        ans_datalen = struct.pack('>H', len(rdata))
        
        resp += ans_name + ans_type + ans_class + ans_ttl + ans_datalen + rdata
        print(f"[MockDNS] Sent A response (127.0.0.2) for query")
        return resp
        
    elif qtype == 28: # AAAA
        return None # Ignore AAAA for simplicity
        
    return None

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('127.0.0.1', 53))
        print("[MockDNS] Listening on 127.0.0.1:53")
    except Exception as e:
        print(f"[MockDNS] Failed to bind to port 53 (requires root): {e}")
        sys.exit(1)
        
    while True:
        data, addr = sock.recvfrom(512)
        resp = build_dns_response(data)
        if resp:
            sock.sendto(resp, addr)

if __name__ == '__main__':
    main()