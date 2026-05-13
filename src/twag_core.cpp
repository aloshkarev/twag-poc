#include "twag_core.hpp"
#include "radius_server.hpp"
#include "dhcp_server.hpp"
#include "data_plane.hpp"
#include <iostream>
#include <netdb.h>
#include <arpa/inet.h>

extern "C" {
#include <freeDiameter/freeDiameter-host.h>
#include <freeDiameter/libfdcore.h>
}

TwagCore::TwagCore(const std::string& config_file) {
    config_ = ConfigManager::load(config_file);
    event_loop_ = std::make_unique<EventLoop>();
    session_manager_ = std::make_unique<SessionManager>();
    sta_interface_ = std::make_unique<StaInterface>(this);
    s2a_interface_ = std::make_unique<S2aInterface>(event_loop_.get(), config_.pgw_ip, this);
    radius_server_ = std::make_unique<RadiusServer>(event_loop_.get(), config_, this);
    dhcp_server_ = std::make_unique<DhcpServer>(event_loop_.get(), this);
    data_plane_ = std::make_unique<DataPlane>(event_loop_.get(), config_, this);
}

TwagCore::~TwagCore() {
    fd_core_shutdown();
    fd_core_wait_shutdown_complete();
}

bool TwagCore::initialize() {
    std::cout << "Initializing TWAG Core..." << std::endl;
    
    if (!event_loop_->initialize()) {
        std::cerr << "Failed to initialize event loop." << std::endl;
        return false;
    }

    if (!radius_server_->initialize()) {
        std::cerr << "Failed to initialize RADIUS server." << std::endl;
        return false;
    }

    if (!data_plane_->initialize()) {
        std::cerr << "Failed to initialize Data Plane." << std::endl;
        return false;
    }

    if (!dhcp_server_->initialize()) {
        std::cerr << "Failed to initialize DHCP server." << std::endl;
        return false;
    }

    // Initialize freeDiameter core
    if (fd_core_initialize() != 0) {
        std::cerr << "Failed to initialize freeDiameter core." << std::endl;
        return false;
    }

    if (fd_core_parseconf(const_cast<char*>(config_.fd_conf_filename.c_str())) != 0) {
        std::cerr << "Failed to parse freeDiameter configuration." << std::endl;
        return false;
    }

    if (fd_core_start() != 0) {
        std::cerr << "Failed to start freeDiameter core." << std::endl;
        return false;
    }

    if (!sta_interface_->initialize()) {
        std::cerr << "Failed to initialize STa interface." << std::endl;
        return false;
    }

    if (!s2a_interface_->initialize()) {
        std::cerr << "Failed to initialize S2a interface." << std::endl;
        return false;
    }
    
    // Set up periodic statistics logging
    if (config_.stats_log_interval_sec > 0) {
        event_loop_->add_timer(config_.stats_log_interval_sec * 1000, [this]() {
            this->log_statistics();
        });
    }

    return true;
}

void TwagCore::handle_radius_access_request(const std::string& mac_addr, const std::string& imsi, const std::string& eap_payload, 
                                          const struct sockaddr_in& client_addr, uint8_t req_id, const uint8_t* req_auth) {
    std::cout << "--- Processing RADIUS Access-Request for " << mac_addr << " ---" << std::endl;
    auto session = session_manager_->get_session(mac_addr);
    if (!session) {
        if (session_manager_->get_active_sessions_count() >= config_.max_active_sessions) {
            std::cerr << "[TWAG] Congestion Control: Rejecting new session for MAC: " << mac_addr << ". Max active sessions reached (" << config_.max_active_sessions << ")." << std::endl;
            session_manager_->increment_rejected();
            radius_server_->send_response(client_addr, 3 /* Access-Reject */, req_id, req_auth, "");
            return;
        }
        session = session_manager_->create_session(mac_addr);
    }
    
    if (!imsi.empty()) {
        session->imsi_ = imsi;
    }
    
    session->radius_client_addr_ = client_addr;
    session->radius_req_id_ = req_id;
    memcpy(session->radius_req_auth_, req_auth, 16);
    
    if (sta_interface_->send_der(session, eap_payload)) {
        std::cout << "DER sent successfully. Waiting asynchronously for DEA..." << std::endl;
    } else {
        std::cerr << "Failed to send DER for UE." << std::endl;
    }
}

void TwagCore::on_dea_received(const std::string& mac_addr, uint32_t result_code, const std::string& eap_payload,
                               const std::string& apn, uint32_t pdn_type, uint32_t ambr_ul, uint32_t ambr_dl, const std::string& pgw_ip) {
    auto session = session_manager_->get_session(mac_addr);
    if (!session || session->get_state() != SessionState::AUTH_PENDING) return;

    if (!apn.empty()) session->apn_ = apn;
    else if (session->apn_.empty()) session->apn_ = config_.apn;

    if (pdn_type != 0) session->pdn_type_ = pdn_type;

    if (ambr_ul != 0) session->ambr_ul_ = ambr_ul;
    if (ambr_dl != 0) session->ambr_dl_ = ambr_dl;

    if (!pgw_ip.empty()) {
        session->pgw_ip_ = pgw_ip;
        std::cout << "[TWAG] Using static P-GW IP from AAA: " << session->pgw_ip_ << std::endl;
    } else {
        std::string apn_fqdn = session->apn_ + ".apn." + config_.aaa_realm;
        std::string resolved_ip = resolve_pgw_snaptr(apn_fqdn);
        
        if (!resolved_ip.empty()) {
            session->pgw_ip_ = resolved_ip;
            std::cout << "[TWAG] Resolved P-GW IP via S-NAPTR: " << session->pgw_ip_ << std::endl;
        } else {
            std::cerr << "[TWAG] S-NAPTR resolution failed for " << apn_fqdn << ". Falling back to default P-GW." << std::endl;
            session->pgw_ip_ = config_.pgw_ip;
        }
    }
    
    // 1001 = DIAMETER_MULTI_ROUND_AUTH
    if (result_code == 1001) {
        std::cout << "Multi-round EAP requested. Sending RADIUS Access-Challenge." << std::endl;
        radius_server_->send_response(session->radius_client_addr_, 11 /* Access-Challenge */, 
                                      session->radius_req_id_, session->radius_req_auth_, eap_payload);
        return;
    }
    
    // 2001 = DIAMETER_SUCCESS
    if (result_code == 2001) {
        std::cout << "Authentication successful. Sending RADIUS Access-Accept and triggering GTP-C..." << std::endl;
        radius_server_->send_response(session->radius_client_addr_, 2 /* Access-Accept */, 
                                      session->radius_req_id_, session->radius_req_auth_, eap_payload);
        
        if (s2a_interface_->send_create_session_request(session)) {
            std::cout << "GTPv2-C Create Session Request sent asynchronously." << std::endl;
            std::string mac = session->get_mac();
            event_loop_->add_timer(3000, [this, mac]() {
                auto s = session_manager_->get_session(mac);
                if (s && s->get_state() == SessionState::GTP_CREATE_PENDING) {
                    std::cerr << "GTP S2a timeout for MAC: " << mac << std::endl;
                    radius_server_->send_response(s->radius_client_addr_, 3 /* Access-Reject */, 
                                                  s->radius_req_id_, s->radius_req_auth_, "");
                    disconnect_ue(mac);
                }
            });
        }
    } else {
        std::cerr << "Authentication failed for MAC: " << mac_addr << " (Result-Code: " << result_code << ")" << std::endl;
        radius_server_->send_response(session->radius_client_addr_, 3 /* Access-Reject */, 
                                      session->radius_req_id_, session->radius_req_auth_, "");
    }
}

void TwagCore::on_gtp_create_response_received(uint32_t dest_teid, bool success, uint32_t pgw_teid, uint32_t ue_ip, uint8_t qci) {
    auto session = session_manager_->get_session_by_teid_c(dest_teid);
    if (!session) {
        std::cerr << "Session not found for TEID: " << dest_teid << std::endl;
        return;
    }
    std::string mac_addr = session->get_mac();

    if (!success) {
        std::cerr << "GTP Tunnel creation failed for MAC: " << mac_addr << std::endl;
        return;
    }
    
    if (session->get_state() != SessionState::GTP_CREATE_PENDING) return;
    
    session->pgw_teid_u_ = pgw_teid;
    session->ue_ip_ = ue_ip;
    session->qci_ = qci;
    
    if (s2a_interface_->setup_kernel_gtpu_tunnel(session)) {
        std::cout << "GTP-U kernel tunnel setup complete." << std::endl;
        session->set_state(SessionState::CONNECTED);
        std::cout << "--- UE " << mac_addr << " fully connected ---" << std::endl;
    }
}

void TwagCore::on_gtp_delete_bearer_request_received(uint32_t dest_teid) {
    auto session = session_manager_->get_session_by_teid_c(dest_teid);
    if (!session) {
        std::cerr << "Session not found for TEID: " << dest_teid << " on Delete Bearer Request." << std::endl;
        return;
    }
    
    std::string mac_addr = session->get_mac();
    std::cout << "--- P-GW Initiated Disconnect for UE " << mac_addr << " (TEID: " << dest_teid << ") ---" << std::endl;
    
    session->set_state(SessionState::DISCONNECTING);

    // 1. Teardown kernel GTP-U tunnel
    s2a_interface_->teardown_kernel_gtpu_tunnel(session);

    // 2. Send Diameter STR to AAA
    sta_interface_->send_str(session);

    // 3. Send RADIUS Disconnect-Request to WLC
    radius_server_->send_disconnect_request(session->radius_client_addr_, mac_addr);

    // 4. Remove session from manager
    session_manager_->remove_session(mac_addr);
    std::cout << "--- UE " << mac_addr << " fully disconnected ---" << std::endl;
}

void TwagCore::on_aaa_abort_session_received(const std::string& mac_addr) {
    auto session = session_manager_->get_session(mac_addr);
    if (!session) {
        std::cerr << "Session not found for MAC: " << mac_addr << " on AAA ASR." << std::endl;
        return;
    }

    std::cout << "--- AAA Initiated Disconnect for UE " << mac_addr << " ---" << std::endl;

    session->set_state(SessionState::DISCONNECTING);

    // 1. Teardown kernel GTP-U tunnel
    s2a_interface_->teardown_kernel_gtpu_tunnel(session);

    // 2. Send GTPv2-C Delete Session to PGW
    s2a_interface_->send_delete_session_request(session);

    // 3. Send RADIUS Disconnect-Request to WLC
    radius_server_->send_disconnect_request(session->radius_client_addr_, mac_addr);

    // 4. Remove session from manager
    session_manager_->remove_session(mac_addr);
    std::cout << "--- UE " << mac_addr << " fully disconnected ---" << std::endl;
}

void TwagCore::disconnect_ue(const std::string& mac_addr) {
    std::cout << "--- Disconnecting UE " << mac_addr << " ---" << std::endl;
    auto session = session_manager_->get_session(mac_addr);
    if (!session) {
        std::cerr << "Session not found for MAC: " << mac_addr << std::endl;
        return;
    }

    // 1. Send Diameter STR to AAA
    sta_interface_->send_str(session);

    // 2. Send GTPv2-C Delete Session to PGW
    s2a_interface_->send_delete_session_request(session);

    // 3. Teardown kernel GTP-U tunnel
    s2a_interface_->teardown_kernel_gtpu_tunnel(session);

    // 4. Remove session from manager
    session_manager_->remove_session(mac_addr);
    std::cout << "--- UE " << mac_addr << " fully disconnected ---" << std::endl;
}

void TwagCore::handle_dhcp_discover(const std::string& mac_addr, uint32_t transaction_id) {
    auto session = session_manager_->get_session(mac_addr);
    if (session && session->get_state() == SessionState::CONNECTED && session->ue_ip_ != 0) {
        dhcp_server_->send_offer(mac_addr, session->ue_ip_, transaction_id);
    } else {
        std::cout << "[TWAG] Ignoring DHCP Discover from " << mac_addr << ". Session not CONNECTED or no IP assigned." << std::endl;
    }
}

void TwagCore::handle_dhcp_request(const std::string& mac_addr, uint32_t transaction_id) {
    auto session = session_manager_->get_session(mac_addr);
    if (session && session->get_state() == SessionState::CONNECTED && session->ue_ip_ != 0) {
        dhcp_server_->send_ack(mac_addr, session->ue_ip_, transaction_id);
    } else {
        std::cout << "[TWAG] Ignoring DHCP Request from " << mac_addr << ". Session not CONNECTED or no IP assigned." << std::endl;
    }
}

void TwagCore::run() {
    std::cout << "TWAG Core event loop running..." << std::endl;
    // We would normally register sockets with event_loop_ here.
    // Since we don't have them yet, we'll just let it run.
    event_loop_->run();
}

std::string TwagCore::resolve_pgw_snaptr(const std::string& apn_fqdn) {
    std::cout << "[TWAG] Performing S-NAPTR query for APN FQDN: " << apn_fqdn << std::endl;
    
    res_init();
    
    unsigned char response[NS_PACKETSZ];
    int len = res_query(apn_fqdn.c_str(), ns_c_in, ns_t_naptr, response, sizeof(response));
    
    if (len < 0) {
        std::cerr << "[TWAG] S-NAPTR res_query failed for " << apn_fqdn << std::endl;
        return "";
    }

    ns_msg handle;
    if (ns_initparse(response, len, &handle) < 0) {
        std::cerr << "[TWAG] Failed to parse DNS response." << std::endl;
        return "";
    }

    int answer_count = ns_msg_count(handle, ns_s_an);
    if (answer_count == 0) {
        std::cout << "[TWAG] No NAPTR records found for " << apn_fqdn << std::endl;
        return "";
    }

    std::string best_replacement = "";
    int best_order = 65536;
    int best_pref = 65536;

    for (int i = 0; i < answer_count; i++) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) continue;

        if (ns_rr_type(rr) == ns_t_naptr) {
            const unsigned char* rdata = ns_rr_rdata(rr);
            int rr_len = ns_rr_rdlen(rr);
            
            if (rr_len < 4) continue;
            
            int order = ns_get16(rdata);
            int pref = ns_get16(rdata + 2);
            const unsigned char* p = rdata + 4;
            
            int flags_len = *p;
            p += 1 + flags_len;
            
            int svc_len = *p;
            std::string services((const char*)(p + 1), svc_len);
            p += 1 + svc_len;
            
            int reg_len = *p;
            p += 1 + reg_len;
            
            char replacement[NS_MAXDNAME];
            if (dn_expand(ns_msg_base(handle), ns_msg_end(handle), p, replacement, sizeof(replacement)) < 0) continue;
            
            std::cout << "[TWAG] Found NAPTR Order: " << order << " Pref: " << pref 
                      << " Svc: " << services << " Repl: " << replacement << std::endl;
                      
            bool is_target_service = (services.find("x-3gpp-pgw:x-s2a-gtp") != std::string::npos);
            
            if (is_target_service || best_replacement.empty()) {
                if (best_replacement.empty() || (order < best_order) || (order == best_order && pref < best_pref)) {
                    best_replacement = replacement;
                    best_order = order;
                    best_pref = pref;
                }
            }
        }
    }
    
    if (best_replacement.empty()) {
        std::cerr << "[TWAG] No valid S-NAPTR replacement found." << std::endl;
        return "";
    }
    
    std::cout << "[TWAG] Selected P-GW FQDN: " << best_replacement << ". Resolving IP..." << std::endl;
    
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(best_replacement.c_str(), nullptr, &hints, &res) == 0) {
        char ip_str[INET6_ADDRSTRLEN];
        std::string final_ip = "";
        if (res->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
            inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
            final_ip = ip_str;
        } else if (res->ai_family == AF_INET6) {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
            inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_str, INET6_ADDRSTRLEN);
            final_ip = ip_str;
        }
        freeaddrinfo(res);
        return final_ip;
    }
    
    std::cerr << "[TWAG] Failed to resolve A/AAAA for P-GW FQDN: " << best_replacement << std::endl;
    return "";
}

void TwagCore::log_statistics() {
    size_t active;
    uint64_t total_conn, total_disconn, rejected;
    session_manager_->get_stats(active, total_conn, total_disconn, rejected);

    std::cout << "\n========================================================\n"
              << "[TWAG STATS] Active Sessions: " << active << "\n"
              << "[TWAG STATS] Total Connections: " << total_conn << "\n"
              << "[TWAG STATS] Total Disconnections: " << total_disconn << "\n"
              << "[TWAG STATS] Rejected Sessions: " << rejected << "\n"
              << "========================================================\n" << std::endl;

    if (config_.stats_log_interval_sec > 0) {
        event_loop_->add_timer(config_.stats_log_interval_sec * 1000, [this]() {
            this->log_statistics();
        });
    }
}
