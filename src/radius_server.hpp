#ifndef RADIUS_SERVER_HPP
#define RADIUS_SERVER_HPP

#include <string>
#include <netinet/in.h>
#include <unordered_map>
#include "event_loop.hpp"
#include "config_manager.hpp"

class TwagCore;

class RadiusServer {
public:
    RadiusServer(EventLoop* event_loop, const TwagConfig& config, TwagCore* core);
    ~RadiusServer();

    bool initialize();
    bool send_response(const struct sockaddr_in& client_addr, uint8_t code, uint8_t id, const uint8_t* req_auth, const std::string& eap_payload);
    bool send_disconnect_request(const struct sockaddr_in& wlc_addr, const std::string& mac_addr);

private:
    void handle_udp_rx(uint32_t events);

    EventLoop* event_loop_;
    TwagConfig config_;
    TwagCore* core_;
    int udp_fd_;
    
    struct sockaddr_in acct_server_addr_;
    std::unordered_map<uint8_t, struct sockaddr_in> pending_acct_reqs_;
};

#endif // RADIUS_SERVER_HPP
