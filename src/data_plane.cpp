#include "data_plane.hpp"
#include "twag_core.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

DataPlane::DataPlane(EventLoop* event_loop, const TwagConfig& config, TwagCore* core)
    : event_loop_(event_loop), config_(config), core_(core), raw_fd_(-1) {
}

DataPlane::~DataPlane() {
    std::cout << "[DataPlane] Cleaning up twag_gre interface." << std::endl;
    system("ip link del twag_gre > /dev/null 2>&1");
}

bool DataPlane::initialize() {
    std::cout << "[DataPlane] Setting up kernel gretap tunnel to WLC (" << config_.wlc_ip << ")" << std::endl;

    // Discover local IP to WLC
    std::string local_ip = "0.0.0.0";
    int temp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (temp_fd >= 0) {
        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(1812); // arbitrary port
        if (inet_pton(AF_INET, config_.wlc_ip.c_str(), &dest_addr.sin_addr) > 0) {
            if (connect(temp_fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) == 0) {
                struct sockaddr_in local_addr;
                socklen_t len = sizeof(local_addr);
                if (getsockname(temp_fd, (struct sockaddr*)&local_addr, &len) == 0) {
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(local_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
                    local_ip = ip_str;
                }
            }
        }
        close(temp_fd);
    }

    if (local_ip == "0.0.0.0") {
        std::cerr << "[DataPlane] Failed to discover local IP to WLC. gretap setup may fail." << std::endl;
    }

    // Clean up any existing interface
    system("ip link del twag_gre > /dev/null 2>&1");

    std::string add_cmd = "ip link add twag_gre type gretap local " + local_ip + " remote " + config_.wlc_ip;
    if (system(add_cmd.c_str()) != 0) {
        std::cerr << "[DataPlane] Failed to create twag_gre interface. (Needs root/CAP_NET_ADMIN?)" << std::endl;
        return false;
    }

    if (system("ip link set twag_gre up") != 0) {
        std::cerr << "[DataPlane] Failed to bring twag_gre up." << std::endl;
    }

    if (system("ip addr add 10.0.0.1/24 dev twag_gre") != 0) {
        std::cerr << "[DataPlane] Failed to assign IP 10.0.0.1 to twag_gre." << std::endl;
    }

    std::cout << "[DataPlane] twag_gre successfully configured." << std::endl;
    return true;
}

void DataPlane::handle_access_rx(uint32_t events) {
    // No longer needed as kernel handles EoGRE decapsulation
}