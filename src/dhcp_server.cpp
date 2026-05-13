#include "dhcp_server.hpp"
#include "twag_core.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <iomanip>
#include <sstream>

// Basic DHCP/BOOTP Header
struct bootp_hdr {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t magic_cookie;
} __attribute__((packed));

DhcpServer::DhcpServer(EventLoop* event_loop, TwagCore* core)
    : event_loop_(event_loop), core_(core), udp_fd_(-1) {
    inet_pton(AF_INET, "10.0.0.1", &server_ip_); // Mock access-side IP
}

DhcpServer::~DhcpServer() {
    if (udp_fd_ >= 0) {
        event_loop_->remove_fd(udp_fd_);
        close(udp_fd_);
    }
}

bool DhcpServer::initialize() {
    udp_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd_ < 0) {
        std::cerr << "Failed to create DHCP UDP socket." << std::endl;
        return false;
    }

    int opt = 1;
    setsockopt(udp_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(udp_fd_, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));

    // Bind specifically to twag_gre
    const char* dev = "twag_gre";
    if (setsockopt(udp_fd_, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev)) < 0) {
        std::cerr << "Warning: Failed to bind DHCP socket to " << dev << ": " << strerror(errno) << " (Needs root?)" << std::endl;
    }

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(67); // DHCP Server port

    if (bind(udp_fd_, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        std::cerr << "Failed to bind DHCP socket to port 67: " << strerror(errno) << std::endl;
        close(udp_fd_);
        udp_fd_ = -1;
        return false;
    }

    auto handler = [this](uint32_t events) { this->handle_udp_rx(events); };
    if (!event_loop_->add_fd(udp_fd_, EPOLLIN, handler)) {
        std::cerr << "Failed to add DHCP UDP socket to event loop." << std::endl;
        return false;
    }

    std::cout << "DHCP Server initialized on port 67." << std::endl;
    return true;
}

void DhcpServer::handle_udp_rx(uint32_t events) {
    if (events & EPOLLIN) {
        uint8_t buffer[2048];
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);
        
        ssize_t n = recvfrom(udp_fd_, buffer, sizeof(buffer), 0, (struct sockaddr*)&src_addr, &addr_len);
        if (n >= sizeof(bootp_hdr)) {
            bootp_hdr* hdr = reinterpret_cast<bootp_hdr*>(buffer);
            
            if (hdr->op == 1 && ntohl(hdr->magic_cookie) == 0x63825363) { // BOOTREQUEST and DHCP magic cookie
                // Extract MAC address
                std::stringstream mac_ss;
                for (int i = 0; i < 6; ++i) {
                    mac_ss << std::hex << std::setw(2) << std::setfill('0') << (int)hdr->chaddr[i];
                    if (i < 5) mac_ss << ":";
                }
                std::string mac_addr = mac_ss.str();
                // To upper case
                for (auto & c: mac_addr) c = toupper(c);

                // Find DHCP Message Type option
                uint8_t msg_type = 0;
                int offset = sizeof(bootp_hdr);
                while (offset < n) {
                    uint8_t opt_code = buffer[offset];
                    if (opt_code == 255) break; // End option
                    if (opt_code == 0) { offset++; continue; } // Pad option
                    
                    uint8_t opt_len = buffer[offset + 1];
                    if (opt_code == 53 && opt_len == 1) { // DHCP Message Type
                        msg_type = buffer[offset + 2];
                        break;
                    }
                    offset += 2 + opt_len;
                }

                if (msg_type == 1) { // DHCP Discover
                    std::cout << "[DHCP] Received Discover from " << mac_addr << std::endl;
                    core_->handle_dhcp_discover(mac_addr, hdr->xid);
                } else if (msg_type == 3) { // DHCP Request
                    std::cout << "[DHCP] Received Request from " << mac_addr << std::endl;
                    core_->handle_dhcp_request(mac_addr, hdr->xid);
                }
            }
        }
    }
}

void DhcpServer::send_dhcp_response(const std::string& mac_addr, uint32_t ue_ip, uint32_t transaction_id, uint8_t msg_type) {
    uint8_t buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    
    bootp_hdr* hdr = reinterpret_cast<bootp_hdr*>(buffer);
    hdr->op = 2; // BOOTREPLY
    hdr->htype = 1; // Ethernet
    hdr->hlen = 6;
    hdr->xid = transaction_id;
    hdr->yiaddr = ue_ip; // P-GW assigned IP (network byte order)
    hdr->siaddr = server_ip_;
    hdr->magic_cookie = htonl(0x63825363);

    // Parse MAC back to bytes
    int mac_bytes[6];
    if (sscanf(mac_addr.c_str(), "%x:%x:%x:%x:%x:%x", 
               &mac_bytes[0], &mac_bytes[1], &mac_bytes[2], 
               &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) == 6) {
        for (int i = 0; i < 6; ++i) hdr->chaddr[i] = (uint8_t)mac_bytes[i];
    }

    int offset = sizeof(bootp_hdr);

    // Option 53: DHCP Message Type
    buffer[offset++] = 53;
    buffer[offset++] = 1;
    buffer[offset++] = msg_type; // 2 for Offer, 5 for Ack

    // Option 1: Subnet Mask (255.255.255.0)
    buffer[offset++] = 1;
    buffer[offset++] = 4;
    uint32_t subnet = htonl(0xFFFFFF00);
    memcpy(buffer + offset, &subnet, 4);
    offset += 4;

    // Option 3: Router
    buffer[offset++] = 3;
    buffer[offset++] = 4;
    memcpy(buffer + offset, &server_ip_, 4);
    offset += 4;

    // Option 51: IP Address Lease Time (1 hour)
    buffer[offset++] = 51;
    buffer[offset++] = 4;
    uint32_t lease = htonl(3600);
    memcpy(buffer + offset, &lease, 4);
    offset += 4;

    // Option 54: Server Identifier
    buffer[offset++] = 54;
    buffer[offset++] = 4;
    memcpy(buffer + offset, &server_ip_, 4);
    offset += 4;

    // Option 6: DNS Server (8.8.8.8)
    buffer[offset++] = 6;
    buffer[offset++] = 4;
    uint32_t dns;
    inet_pton(AF_INET, "8.8.8.8", &dns);
    memcpy(buffer + offset, &dns, 4);
    offset += 4;

    buffer[offset++] = 255; // End option

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(68); // DHCP Client port
    dest_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST); // Broadcast response

    if (sendto(udp_fd_, buffer, offset, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        std::cerr << "Failed to send DHCP response: " << strerror(errno) << std::endl;
    } else {
        std::cout << "[DHCP] Sent " << (msg_type == 2 ? "Offer" : "Ack") << " to " << mac_addr << std::endl;
    }
}

void DhcpServer::send_offer(const std::string& mac_addr, uint32_t ue_ip, uint32_t transaction_id) {
    send_dhcp_response(mac_addr, ue_ip, transaction_id, 2); // 2 = Offer
}

void DhcpServer::send_ack(const std::string& mac_addr, uint32_t ue_ip, uint32_t transaction_id) {
    send_dhcp_response(mac_addr, ue_ip, transaction_id, 5); // 5 = Ack
}