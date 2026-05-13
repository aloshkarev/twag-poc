#include "s2a_interface.hpp"
#include "twag_core.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

// GTPv2-C Headers
extern "C" {
#include <gtp_ies.h>
#include <gtp_messages.h>
#include <gtp_messages_encoder.h>
#include <gtp_messages_decoder.h>
}

// GTP-U Netlink Headers
extern "C" {
#include <libgtpnl/gtp.h>
#include <libgtpnl/gtpnl.h>
}

static uint64_t encode_imsi_bcd(const std::string& imsi) {
    uint64_t packed = 0;
    uint8_t* p = reinterpret_cast<uint8_t*>(&packed);
    int len = imsi.length();
    if (len > 15) len = 15;
    
    for (int i = 0; i < 8; i++) {
        uint8_t low = (i * 2 < len) ? (imsi[i * 2] - '0') : 0x0f;
        uint8_t high = (i * 2 + 1 < len) ? (imsi[i * 2 + 1] - '0') : 0x0f;
        p[i] = (high << 4) | low;
    }
    return packed;
}

static uint8_t map_qci_to_dscp(uint8_t qci) {
    switch (qci) {
        case 1: return 46; // Expedited Forwarding (Voice)
        case 2: return 46; // Expedited Forwarding (Video)
        case 5: return 24; // CS3 (IMS Signaling)
        case 6: return 18; // AF21
        case 7: return 20; // AF22
        case 8: return 10; // AF11
        case 9: return 0;  // Default (Best Effort)
        default: return 0;
    }
}

S2aInterface::S2aInterface(EventLoop* event_loop, const std::string& pgw_ip, TwagCore* core) 
    : event_loop_(event_loop), core_(core), udp_fd_(-1), pgw_ip_(pgw_ip) {
    memset(&pgw_addr_, 0, sizeof(pgw_addr_));
}

S2aInterface::~S2aInterface() {
    if (udp_fd_ >= 0) {
        event_loop_->remove_fd(udp_fd_);
        close(udp_fd_);
    }
}

bool S2aInterface::initialize() {
    udp_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd_ < 0) {
        std::cerr << "Failed to create S2a UDP socket." << std::endl;
        return false;
    }

    int opt = 1;
    setsockopt(udp_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(udp_fd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(2123); // GTP-C port

    if (bind(udp_fd_, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        std::cerr << "Failed to bind UDP socket to port 2123: " << strerror(errno) << std::endl;
        close(udp_fd_);
        udp_fd_ = -1;
        return false;
    }

    pgw_addr_.sin_family = AF_INET;
    pgw_addr_.sin_port = htons(2123);
    if (inet_pton(AF_INET, pgw_ip_.c_str(), &pgw_addr_.sin_addr) <= 0) {
        std::cerr << "Invalid PGW IP address: " << pgw_ip_ << std::endl;
        return false;
    }

    auto handler = [this](uint32_t events) { this->handle_udp_rx(events); };
    if (!event_loop_->add_fd(udp_fd_, EPOLLIN, handler)) {
        std::cerr << "Failed to add S2a UDP socket to event loop." << std::endl;
        return false;
    }

    std::cout << "S2a Interface initialized on port 2123, PGW=" << pgw_ip_ << std::endl;
    return true;
}

void S2aInterface::handle_udp_rx(uint32_t events) {
    if (events & EPOLLIN) {
        uint8_t buffer[2048];
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);
        
        ssize_t n = recvfrom(udp_fd_, buffer, sizeof(buffer), 0, (struct sockaddr*)&src_addr, &addr_len);
        if (n > 0) {
            std::cout << "[S2a] Received " << n << " bytes on S2a (GTPv2-C) interface." << std::endl;
            
            // Check if it's a Create Session Response (Type 33)
            if (n >= 4 && buffer[1] == 33) {
                create_sess_rsp_t rsp;
                memset(&rsp, 0, sizeof(rsp));
                if (decode_create_sess_rsp(buffer, &rsp) > 0) {
                    std::cout << "[S2a] Parsed Create Session Response." << std::endl;
                    
                    uint32_t pgw_teid = 0;
                    uint32_t ue_ip = 0;
                    uint8_t qci = 9; // Default Best Effort
                    
                    if (rsp.bearer_count > 0) {
                        if (rsp.bearer_contexts_created[0].s2a_u_pgw_fteid.header.type != 0) {
                            pgw_teid = rsp.bearer_contexts_created[0].s2a_u_pgw_fteid.teid_gre_key;
                        } else if (rsp.bearer_contexts_created[0].s5s8_u_pgw_fteid.header.type != 0) {
                            pgw_teid = rsp.bearer_contexts_created[0].s5s8_u_pgw_fteid.teid_gre_key;
                        }
                        
                        if (rsp.bearer_contexts_created[0].bearer_lvl_qos.header.type != 0) {
                            qci = rsp.bearer_contexts_created[0].bearer_lvl_qos.qci;
                        }
                    }
                    
                    if (rsp.paa.header.type != 0) {
                        ue_ip = (uint32_t)(rsp.paa.pdn_addr_and_pfx & 0xFFFFFFFF);
                    }
                    
                    uint32_t dest_teid = 0;
                    if (buffer[0] & 0x08) { // TEID flag
                        dest_teid = ntohl(*(uint32_t*)(buffer + 4));
                    }
                    if (core_) core_->on_gtp_create_response_received(dest_teid, true, pgw_teid, ue_ip, qci);
                }
            } else if (n >= 4 && buffer[1] == 99) { // Delete Bearer Request
                del_bearer_req_t req;
                memset(&req, 0, sizeof(req));
                if (decode_del_bearer_req(buffer, &req) > 0) {
                    std::cout << "[S2a] Parsed Delete Bearer Request." << std::endl;
                    
                    uint32_t dest_teid = 0;
                    if (buffer[0] & 0x08) { // TEID flag
                        dest_teid = ntohl(*(uint32_t*)(buffer + 4));
                    }

                    del_bearer_rsp_t rsp;
                    memset(&rsp, 0, sizeof(rsp));
                    rsp.header.gtpc.version = 2;
                    rsp.header.gtpc.teid_flag = 0;
                    rsp.header.gtpc.message_type = 100; // DEL_BEARER_RSP
                    if (buffer[0] & 0x08) {
                        rsp.header.teid.no_teid.seq = req.header.teid.has_teid.seq;
                    } else {
                        rsp.header.teid.no_teid.seq = req.header.teid.no_teid.seq;
                    }
                    
                    rsp.cause.header.type = GTP_IE_CAUSE;
                    rsp.cause.header.len = 2;
                    rsp.cause.cause_value = 16; // Request accepted

                    uint8_t rsp_buffer[1024];
                    int rsp_len = encode_del_bearer_rsp(&rsp, rsp_buffer);
                    if (rsp_len > 0) {
                        sendto(udp_fd_, rsp_buffer, rsp_len, 0, (struct sockaddr*)&src_addr, addr_len);
                        std::cout << "[S2a] Sent Delete Bearer Response." << std::endl;
                    }

                    if (core_) core_->on_gtp_delete_bearer_request_received(dest_teid);
                }
            }
        }
    }
}

bool S2aInterface::send_create_session_request(std::shared_ptr<UeSession> session) {
    std::cout << "Sending Create Session Request for UE MAC: " << session->get_mac() << std::endl;
    
    create_sess_req_t req;
    memset(&req, 0, sizeof(req));
    
    // Header
    req.header.gtpc.version = 2;
    req.header.gtpc.teid_flag = 0; // Create Session Req usually has TEID=0 for initial message
    req.header.gtpc.message_type = CREATE_SESS_REQ;
    req.header.teid.no_teid.seq = 1; // Dummy sequence
    
    // IMSI (Mandatory)
    req.imsi.header.type = GTP_IE_IMSI;
    req.imsi.header.len = 8;
    req.imsi.header.instance = 0;
    req.imsi.imsi_number_digits = encode_imsi_bcd(session->imsi_);
    
    // RAT Type (Mandatory)
    req.rat_type.header.type = GTP_IE_RAT_TYPE;
    req.rat_type.header.len = 1;
    req.rat_type.header.instance = 0;
    req.rat_type.rat_type = 3; // WLAN
    
    // Get local IP for F-TEID
    uint32_t local_ip = htonl(INADDR_LOOPBACK);
    int temp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (temp_fd >= 0) {
        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(2123);
        std::string dest_ip = session->pgw_ip_;
        if (dest_ip.empty()) dest_ip = core_->get_config().pgw_ip;
        inet_pton(AF_INET, dest_ip.c_str(), &dest_addr.sin_addr);
        
        if (connect(temp_fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) == 0) {
            struct sockaddr_in local_addr;
            socklen_t len = sizeof(local_addr);
            if (getsockname(temp_fd, (struct sockaddr*)&local_addr, &len) == 0) {
                local_ip = local_addr.sin_addr.s_addr;
            }
        }
        close(temp_fd);
    }
    
    // Sender F-TEID for Control Plane (Mandatory)
    req.sender_fteid_ctl_plane.header.type = GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT;
    req.sender_fteid_ctl_plane.header.len = 9;
    req.sender_fteid_ctl_plane.header.instance = 0;
    req.sender_fteid_ctl_plane.v4 = 1;
    req.sender_fteid_ctl_plane.interface_type = 0; // S2a TWAN GTP-C
    req.sender_fteid_ctl_plane.teid_gre_key = session->gtp_teid_c_;
    req.sender_fteid_ctl_plane.ipv4_address = local_ip;
    
    // APN (Mandatory)
    req.apn.header.type = GTP_IE_ACC_PT_NAME;
    req.apn.header.instance = 0;
    
    std::string apn = session->apn_;
    if (apn.empty()) apn = core_->get_config().apn;
    req.apn.header.len = apn.length() + 1;
    req.apn.apn[0] = apn.length(); // Length prefix
    memcpy(req.apn.apn + 1, apn.c_str(), apn.length());

    // PDN Type (Mandatory)
    req.pdn_type.header.type = GTP_IE_PDN_TYPE;
    req.pdn_type.header.len = 1;
    req.pdn_type.header.instance = 0;
    req.pdn_type.pdn_type_pdn_type = session->pdn_type_;

    // APN-AMBR
    req.apn_ambr.header.type = GTP_IE_AGG_MAX_BIT_RATE;
    req.apn_ambr.header.len = 8;
    req.apn_ambr.header.instance = 0;
    req.apn_ambr.apn_ambr_uplnk = htonl(session->ambr_ul_ ? session->ambr_ul_ : 1000000);
    req.apn_ambr.apn_ambr_dnlnk = htonl(session->ambr_dl_ ? session->ambr_dl_ : 1000000);

    uint8_t buffer[2048];
    int encoded_len = encode_create_sess_req(&req, buffer);
    if (encoded_len < 0) {
        std::cerr << "Failed to encode Create Session Request." << std::endl;
        return false;
    }
    
    std::cout << "Encoded Create Session Request: " << encoded_len << " bytes." << std::endl;
    
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(2123);
    std::string dest_ip = session->pgw_ip_;
    if (dest_ip.empty()) dest_ip = core_->get_config().pgw_ip;
    if (inet_pton(AF_INET, dest_ip.c_str(), &dest_addr.sin_addr) <= 0) {
        std::cerr << "Invalid PGW IP address: " << dest_ip << std::endl;
        return false;
    }

    if (sendto(udp_fd_, buffer, encoded_len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        std::cerr << "Failed to send Create Session Request: " << strerror(errno) << std::endl;
        return false;
    }
    
    session->set_state(SessionState::GTP_CREATE_PENDING);
    return true;
}

bool S2aInterface::setup_kernel_gtpu_tunnel(std::shared_ptr<UeSession> session) {
    std::cout << "Setting up kernel GTP-U tunnel for UE MAC: " << session->get_mac() << std::endl;
    
    int fd0 = socket(AF_INET, SOCK_DGRAM, 0);
    int fd1 = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (gtp_dev_create(-1, "gtp0", fd0, fd1) < 0) {
        std::cerr << "Failed to create gtp0 device (needs root?): " << strerror(errno) << std::endl;
    } else {
        std::cout << "Successfully created gtp0 device." << std::endl;
    }
    
    struct mnl_socket *nl = genl_socket_open();
    if (!nl) {
        std::cerr << "Failed to open genl socket." << std::endl;
        close(fd0);
        close(fd1);
        return false;
    }
    
    int genl_id = genl_lookup_family(nl, "gtp");
    if (genl_id < 0) {
        std::cerr << "Failed to lookup gtp genl family." << std::endl;
        genl_socket_close(nl);
        close(fd0);
        close(fd1);
        return false;
    }
    
    struct gtp_tunnel *t = gtp_tunnel_alloc();
    if (!t) {
        std::cerr << "Failed to allocate gtp_tunnel." << std::endl;
        genl_socket_close(nl);
        close(fd0);
        close(fd1);
        return false;
    }
    
    gtp_tunnel_set_ifidx(t, 0); // Should be if_nametoindex("gtp0")
    gtp_tunnel_set_version(t, 1); // GTPv1-U
    gtp_tunnel_set_i_tei(t, session->gtp_teid_u_); // Incoming TEID (local to TWAG)
    gtp_tunnel_set_o_tei(t, session->pgw_teid_u_); // Outgoing TEID to PGW
    
    struct in_addr ms_addr, sgsn_addr;
    ms_addr.s_addr = session->ue_ip_; // UE IP from PAA
    inet_pton(AF_INET, pgw_ip_.c_str(), &sgsn_addr); // PGW IP
    
    gtp_tunnel_set_ms_ip4(t, &ms_addr);
    gtp_tunnel_set_sgsn_ip4(t, &sgsn_addr);
    
    if (gtp_add_tunnel(genl_id, nl, t) < 0) {
        std::cerr << "Failed to add gtp tunnel: " << strerror(errno) << std::endl;
    } else {
        std::cout << "Successfully added GTP-U tunnel to kernel." << std::endl;
        
        // Setup L3 routing for the UE IP to go through gtp0
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(session->ue_ip_), ip_str, INET_ADDRSTRLEN);
        
        std::string route_cmd = std::string("ip route add ") + ip_str + " dev gtp0";
        std::cout << "Executing: " << route_cmd << std::endl;
        int ret = system(route_cmd.c_str());
        if (ret != 0) {
            std::cerr << "Warning: Failed to add IP route for UE (ret=" << ret << ")" << std::endl;
        }
    }
    
    gtp_tunnel_free(t);
    genl_socket_close(nl);
    close(fd0);
    close(fd1);
    
    return true;
}

bool S2aInterface::send_delete_session_request(std::shared_ptr<UeSession> session) {
    std::cout << "Sending Delete Session Request for UE MAC: " << session->get_mac() << std::endl;
    
    del_sess_req_t req;
    memset(&req, 0, sizeof(req));
    
    // Header
    req.header.gtpc.version = 2;
    req.header.gtpc.teid_flag = 1;
    req.header.gtpc.message_type = DEL_SESS_REQ;
    req.header.teid.has_teid.seq = 2; // Dummy sequence for delete
    req.header.teid.has_teid.teid = session->pgw_teid_c_; // Target TEID
    
    // Linked EPS Bearer ID (LBI)
    req.lbi.header.type = GTP_IE_EPS_BEARER_ID;
    req.lbi.header.len = 1;
    req.lbi.header.instance = 0;
    req.lbi.ebi_ebi = 5; // Default LBI

    uint8_t buffer[1024];
    int encoded_len = encode_del_sess_req(&req, buffer);
    if (encoded_len < 0) {
        std::cerr << "Failed to encode Delete Session Request." << std::endl;
        return false;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(2123);
    std::string dest_ip = session->pgw_ip_;
    if (dest_ip.empty()) dest_ip = core_->get_config().pgw_ip;
    if (inet_pton(AF_INET, dest_ip.c_str(), &dest_addr.sin_addr) <= 0) {
        std::cerr << "Invalid PGW IP address: " << dest_ip << std::endl;
        return false;
    }

    if (sendto(udp_fd_, buffer, encoded_len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        std::cerr << "Failed to send Delete Session Request: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

bool S2aInterface::teardown_kernel_gtpu_tunnel(std::shared_ptr<UeSession> session) {
    std::cout << "Tearing down kernel GTP-U tunnel for UE MAC: " << session->get_mac() << std::endl;
    
    // Remove L3 routing
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(session->ue_ip_), ip_str, INET_ADDRSTRLEN);
    std::string route_cmd = std::string("ip route del ") + ip_str + " dev gtp0";
    std::cout << "Executing: " << route_cmd << std::endl;
    system(route_cmd.c_str());
    
    // Remove DSCP marking
    uint8_t dscp = map_qci_to_dscp(session->qci_);
    if (dscp != 0) {
        std::string iptables_cmd = std::string("iptables -t mangle -D POSTROUTING -o twag_gre -d ") + ip_str + 
                                   " -j DSCP --set-dscp " + std::to_string(dscp);
        std::cout << "Removing QoS: " << iptables_cmd << std::endl;
        system(iptables_cmd.c_str());
    }

    return true;
}
