#ifndef S2A_INTERFACE_HPP
#define S2A_INTERFACE_HPP

#include "ue_session.hpp"
#include "event_loop.hpp"
#include <memory>
#include <string>
#include <netinet/in.h>

class TwagCore;

class S2aInterface {
public:
    S2aInterface(EventLoop* event_loop, const std::string& pgw_ip, TwagCore* core);
    ~S2aInterface();

    bool initialize();

    // GTPv2-C Control Plane
    bool send_create_session_request(std::shared_ptr<UeSession> session);
    bool send_delete_session_request(std::shared_ptr<UeSession> session);
    
    // GTP-U User Plane via Netlink
    bool setup_kernel_gtpu_tunnel(std::shared_ptr<UeSession> session);
    bool teardown_kernel_gtpu_tunnel(std::shared_ptr<UeSession> session);

private:
    void handle_udp_rx(uint32_t events);

    EventLoop* event_loop_;
    TwagCore* core_;
    int udp_fd_;
    std::string pgw_ip_;
    struct sockaddr_in pgw_addr_;
};

#endif // S2A_INTERFACE_HPP
