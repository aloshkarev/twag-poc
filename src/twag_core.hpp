#ifndef TWAG_CORE_HPP
#define TWAG_CORE_HPP

#include <string>
#include <memory>
#include <resolv.h>
#include <arpa/nameser.h>
#include "event_loop.hpp"
#include "session_manager.hpp"
#include "sta_interface.hpp"
#include "s2a_interface.hpp"
#include "config_manager.hpp"

class RadiusServer;
class DhcpServer;
class DataPlane;

class TwagCore {
public:
    TwagCore(const std::string& config_file);
    ~TwagCore();

    bool initialize();
    void run();
    
    void handle_radius_access_request(const std::string& mac_addr, const std::string& imsi, const std::string& eap_payload, 
                                      const struct sockaddr_in& client_addr, uint8_t req_id, const uint8_t* req_auth);
    void disconnect_ue(const std::string& mac_addr);

    // DHCP Handlers
    void handle_dhcp_discover(const std::string& mac_addr, uint32_t transaction_id);
    void handle_dhcp_request(const std::string& mac_addr, uint32_t transaction_id);

    const TwagConfig& get_config() const { return config_; }

    // Callbacks from async interfaces
    void on_dea_received(const std::string& session_id, uint32_t result_code, const std::string& eap_payload,
                         const std::string& apn, uint32_t pdn_type, uint32_t ambr_ul, uint32_t ambr_dl, const std::string& pgw_ip);
    void on_gtp_create_response_received(uint32_t dest_teid, bool success, uint32_t pgw_teid, uint32_t ue_ip, uint8_t qci);
    void on_gtp_delete_bearer_request_received(uint32_t dest_teid);
    void on_aaa_abort_session_received(const std::string& mac_addr);

private:
    std::string resolve_pgw_snaptr(const std::string& apn_fqdn);
    void log_statistics();

    TwagConfig config_;
    std::unique_ptr<EventLoop> event_loop_;
    std::unique_ptr<SessionManager> session_manager_;
    std::unique_ptr<StaInterface> sta_interface_;
    std::unique_ptr<S2aInterface> s2a_interface_;
    std::unique_ptr<RadiusServer> radius_server_;
    std::unique_ptr<DhcpServer> dhcp_server_;
    std::unique_ptr<DataPlane> data_plane_;
};

#endif // TWAG_CORE_HPP
