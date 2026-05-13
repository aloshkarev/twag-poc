#ifndef UE_SESSION_HPP
#define UE_SESSION_HPP

#include <string>
#include <cstdint>
#include <netinet/in.h>

enum class SessionState {
    INIT,
    AUTH_PENDING,
    GTP_CREATE_PENDING,
    CONNECTED,
    DISCONNECTING
};

class UeSession {
public:
    UeSession(const std::string& mac_addr) : mac_address_(mac_addr), state_(SessionState::INIT),
                                            gtp_teid_c_(0), gtp_teid_u_(0), pdn_type_(1), ambr_ul_(0), ambr_dl_(0), qci_(0) {}

    std::string get_mac() const { return mac_address_; }
    SessionState get_state() const { return state_; }
    void set_state(SessionState state) { state_ = state; }

    std::string imsi_;
    std::string ip_address_;
    uint32_t ue_ip_;
    std::string diameter_session_id_;
    uint32_t gtp_teid_c_;
    uint32_t gtp_teid_u_;
    uint32_t pgw_teid_c_;
    uint32_t pgw_teid_u_;
    std::string pgw_ip_;
    std::string apn_;
    uint32_t pdn_type_;
    uint32_t ambr_ul_;
    uint32_t ambr_dl_;
    uint8_t qci_;

    // RADIUS routing info for async replies
    struct sockaddr_in radius_client_addr_;
    uint8_t radius_req_id_;
    uint8_t radius_req_auth_[16];

private:
    std::string mac_address_;
    SessionState state_;
};

#endif // UE_SESSION_HPP
