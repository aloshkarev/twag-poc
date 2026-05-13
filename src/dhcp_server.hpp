#ifndef DHCP_SERVER_HPP
#define DHCP_SERVER_HPP

#include <string>
#include <netinet/in.h>
#include "event_loop.hpp"
#include "ue_session.hpp"

class TwagCore;

class DhcpServer {
public:
    DhcpServer(EventLoop* event_loop, TwagCore* core);
    ~DhcpServer();

    bool initialize();

    void send_offer(const std::string& mac_addr, uint32_t ue_ip, uint32_t transaction_id);
    void send_ack(const std::string& mac_addr, uint32_t ue_ip, uint32_t transaction_id);

private:
    void handle_udp_rx(uint32_t events);
    void send_dhcp_response(const std::string& mac_addr, uint32_t ue_ip, uint32_t transaction_id, uint8_t msg_type);

    EventLoop* event_loop_;
    TwagCore* core_;
    int udp_fd_;
    uint32_t server_ip_; // Local access-side IP
};

#endif // DHCP_SERVER_HPP