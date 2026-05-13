#include "radius_server.hpp"
#include "twag_core.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>

// Minimal RADIUS Header
struct radius_hdr {
    uint8_t code;
    uint8_t id;
    uint16_t length;
    uint8_t authenticator[16];
} __attribute__((packed));

RadiusServer::RadiusServer(EventLoop* event_loop, const TwagConfig& config, TwagCore* core)
    : event_loop_(event_loop), config_(config), core_(core), udp_fd_(-1) {}

RadiusServer::~RadiusServer() {
    if (udp_fd_ >= 0) {
        event_loop_->remove_fd(udp_fd_);
        close(udp_fd_);
    }
}

bool RadiusServer::initialize() {
    udp_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd_ < 0) {
        std::cerr << "Failed to create RADIUS UDP socket." << std::endl;
        return false;
    }

    int opt = 1;
    setsockopt(udp_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(config_.radius_port);

    if (bind(udp_fd_, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        std::cerr << "Failed to bind RADIUS socket to port " << config_.radius_port << ": " << strerror(errno) << std::endl;
        close(udp_fd_);
        udp_fd_ = -1;
        return false;
    }

    auto handler = [this](uint32_t events) { this->handle_udp_rx(events); };
    if (!event_loop_->add_fd(udp_fd_, EPOLLIN, handler)) {
        std::cerr << "Failed to add RADIUS UDP socket to event loop." << std::endl;
        return false;
    }

    std::cout << "RADIUS Server initialized on port " << config_.radius_port << std::endl;
    return true;
}

void RadiusServer::handle_udp_rx(uint32_t events) {
    if (events & EPOLLIN) {
        char buffer[4096];
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);
        
        ssize_t n = recvfrom(udp_fd_, buffer, sizeof(buffer), 0, (struct sockaddr*)&src_addr, &addr_len);
        if (n >= sizeof(radius_hdr)) {
            radius_hdr* hdr = reinterpret_cast<radius_hdr*>(buffer);
            uint16_t rad_len = ntohs(hdr->length);
            
            std::cout << "[RADIUS] Received packet from " << inet_ntoa(src_addr.sin_addr) 
                      << ":" << ntohs(src_addr.sin_port) 
                      << " Code: " << (int)hdr->code 
                      << " Length: " << rad_len << std::endl;
            
            if (rad_len > n || rad_len < sizeof(radius_hdr)) {
                std::cerr << "[RADIUS] Invalid length" << std::endl;
                return;
            }

            // Parse attributes
            std::string mac_addr = "00:11:22:33:44:55"; // Default fallback
            std::string eap_payload = "dummy_eap";
            uint32_t acct_status_type = 0;
            
            int offset = sizeof(radius_hdr);
            while (offset + 2 <= rad_len) {
                uint8_t attr_type = buffer[offset];
                uint8_t attr_len = buffer[offset + 1];
                
                if (attr_len < 2 || offset + attr_len > rad_len) break;
                
                if (attr_type == 31) { // Calling-Station-Id (MAC address)
                    mac_addr = std::string(buffer + offset + 2, attr_len - 2);
                    std::cout << "[RADIUS] Parsed Calling-Station-Id: " << mac_addr << std::endl;
                } else if (attr_type == 79) { // EAP-Message
                    // Note: EAP messages can be fragmented across multiple attributes.
                    // For PoC simplicity, we assume single or concat.
                    eap_payload = std::string(buffer + offset + 2, attr_len - 2);
                    std::cout << "[RADIUS] Parsed EAP-Message (len=" << attr_len - 2 << ")" << std::endl;
                } else if (attr_type == 4) { // Acct-Status-Type
                    if (attr_len == 6) {
                        uint32_t val;
                        memcpy(&val, buffer + offset + 2, 4);
                        acct_status_type = ntohl(val);
                        std::cout << "[RADIUS] Parsed Acct-Status-Type: " << acct_status_type << std::endl;
                    }
                }
                
                offset += attr_len;
            }
            
            // Code 1 is Access-Request
            if (hdr->code == 1) {
                // Extract IMSI from EAP-Identity if present.
                // EAP: Code(1)=2(Response), Id(1), Len(2), Type(1)=1(Identity), Data
                std::string imsi;
                if (eap_payload.length() >= 5 && eap_payload[0] == 2 && eap_payload[4] == 1) {
                    std::string identity = eap_payload.substr(5);
                    
                    // 1. Strip Visited Realm
                    size_t at_pos = identity.find('@');
                    std::string username = (at_pos != std::string::npos) ? identity.substr(0, at_pos) : identity;
                    
                    // 2. Handle Decorated NAI (homerealm!username)
                    size_t bang_pos = username.find_last_of('!');
                    if (bang_pos != std::string::npos) {
                        username = username.substr(bang_pos + 1);
                    }
                    
                    // 3. Handle 3GPP EAP Prefixes (TS 23.003)
                    if (!username.empty()) {
                        char prefix = username[0];
                        if (prefix == '0' || prefix == '1' || prefix == '6') {
                            imsi = username.substr(1);
                        } else {
                            // No known prefix, might be a pseudonym or already pure IMSI
                            imsi = username;
                            std::cout << "[RADIUS] Warning: NAI does not start with known 3GPP prefix (0, 1, 6). Found: " << prefix << std::endl;
                        }
                    }
                }
                std::cout << "[RADIUS] Triggering UE attach for " << mac_addr << " (IMSI: " << imsi << ")" << std::endl;
                core_->handle_radius_access_request(mac_addr, imsi, eap_payload, src_addr, hdr->id, hdr->authenticator);
            } else if (hdr->code == 4) { // Accounting-Request
                if (acct_status_type == 2) { // Stop
                    std::cout << "[RADIUS] Received Accounting Stop. Triggering UE disconnect for " << mac_addr << std::endl;
                    core_->disconnect_ue(mac_addr);
                } else {
                    std::cout << "[RADIUS] Received Accounting Request (Type: " << acct_status_type << ") for " << mac_addr << std::endl;
                }
                
                if (!config_.acct_server_ip.empty()) {
                    pending_acct_reqs_[hdr->id] = src_addr;
                    sendto(udp_fd_, buffer, rad_len, 0, (struct sockaddr*)&acct_server_addr_, sizeof(acct_server_addr_));
                    std::cout << "[RADIUS] Proxied Accounting-Request (ID " << (int)hdr->id << ") to upstream server." << std::endl;
                } else {
                    // Send Accounting-Response (Code 5)
                    send_response(src_addr, 5, hdr->id, hdr->authenticator, "");
                }
            } else if (hdr->code == 5) { // Accounting-Response
                if (!config_.acct_server_ip.empty() && src_addr.sin_addr.s_addr == acct_server_addr_.sin_addr.s_addr) {
                    auto it = pending_acct_reqs_.find(hdr->id);
                    if (it != pending_acct_reqs_.end()) {
                        sendto(udp_fd_, buffer, rad_len, 0, (struct sockaddr*)&(it->second), sizeof(struct sockaddr_in));
                        std::cout << "[RADIUS] Proxied Accounting-Response (ID " << (int)hdr->id << ") to WLC." << std::endl;
                        pending_acct_reqs_.erase(it);
                    }
                }
            }
        }
    }
}

bool RadiusServer::send_response(const struct sockaddr_in& client_addr, uint8_t code, uint8_t id, const uint8_t* req_auth, const std::string& eap_payload) {
    uint8_t buffer[4096];
    radius_hdr* hdr = reinterpret_cast<radius_hdr*>(buffer);
    hdr->code = code;
    hdr->id = id;
    
    // In a real implementation we would calculate MD5 for the authenticator
    // using the config_.radius_secret. For PoC we just copy the request auth or zero it.
    memcpy(hdr->authenticator, req_auth, 16);
    
    int offset = sizeof(radius_hdr);
    
    if (!eap_payload.empty()) {
        buffer[offset] = 79; // EAP-Message
        buffer[offset + 1] = eap_payload.length() + 2;
        memcpy(buffer + offset + 2, eap_payload.data(), eap_payload.length());
        offset += eap_payload.length() + 2;
    }
    
    hdr->length = htons(offset);
    
    if (sendto(udp_fd_, buffer, offset, 0, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0) {
        std::cerr << "Failed to send RADIUS response: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

bool RadiusServer::send_disconnect_request(const struct sockaddr_in& wlc_addr, const std::string& mac_addr) {
    uint8_t buffer[1024];
    radius_hdr* hdr = reinterpret_cast<radius_hdr*>(buffer);
    hdr->code = 40; // Disconnect-Request
    hdr->id = 1; // Random or sequence
    memset(hdr->authenticator, 0, 16); // Should be Message-Authenticator

    int offset = sizeof(radius_hdr);

    // Calling-Station-Id (Attribute 31)
    if (!mac_addr.empty()) {
        buffer[offset] = 31;
        buffer[offset + 1] = mac_addr.length() + 2;
        memcpy(buffer + offset + 2, mac_addr.data(), mac_addr.length());
        offset += mac_addr.length() + 2;
    }

    hdr->length = htons(offset);

    // WLC uses port 3799 for Disconnect-Request/CoA
    struct sockaddr_in target_addr = wlc_addr;
    target_addr.sin_port = htons(3799);

    if (sendto(udp_fd_, buffer, offset, 0, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
        std::cerr << "Failed to send RADIUS Disconnect-Request: " << strerror(errno) << std::endl;
        return false;
    }
    std::cout << "[RADIUS] Sent Disconnect-Request to WLC for MAC: " << mac_addr << std::endl;
    return true;
}
