#ifndef CONFIG_MANAGER_HPP
#define CONFIG_MANAGER_HPP

#include <string>
#include <cstdint>

struct TwagConfig {
    std::string pgw_ip;
    std::string radius_secret;
    int radius_port;
    std::string aaa_realm;
    std::string apn;
    std::string eap_domain;
    std::string fd_conf_filename;
    std::string access_interface;
    std::string wlc_ip;
    std::string acct_server_ip;
    int acct_server_port;
    uint32_t max_active_sessions;
    uint32_t stats_log_interval_sec;
};

class ConfigManager {
public:
    static TwagConfig load(const std::string& filename);
};

#endif // CONFIG_MANAGER_HPP
