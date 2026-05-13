#include "config_manager.hpp"
#include <json/json.hpp>
#include <fstream>
#include <sstream>
#include <iostream>

TwagConfig ConfigManager::load(const std::string& filename) {
    TwagConfig config;
    // Defaults
    config.pgw_ip = "127.0.0.1";
    config.radius_port = 1812;
    config.radius_secret = "testing123";
    config.aaa_realm = "epc.mnc001.mcc001.3gppnetwork.org";
    config.apn = "internet";
    config.eap_domain = "wlan.mnc001.mcc001.3gppnetwork.org";
    config.fd_conf_filename = "twag_fd.conf";
    config.access_interface = "lo"; // fallback for PoC
    config.wlc_ip = "127.0.0.1";
    config.acct_server_ip = ""; // Empty disables proxy
    config.acct_server_port = 1813;

    std::ifstream ifs(filename);
    if (!ifs.is_open()) {
        std::cerr << "Config file " << filename << " not found. Using defaults." << std::endl;
        return config;
    }

    std::stringstream buffer;
    buffer << ifs.rdbuf();

    auto json = yajson::parse(buffer.str());
    if (json.is_object()) {
        if (json.contains("pgw_ip") && json["pgw_ip"].is_string()) {
            config.pgw_ip = json["pgw_ip"].as_string();
        }
        if (json.contains("radius_port") && json["radius_port"].is_integer()) {
            config.radius_port = json["radius_port"].as_integer();
        }
        if (json.contains("radius_secret") && json["radius_secret"].is_string()) {
            config.radius_secret = json["radius_secret"].as_string();
        }
        if (json.contains("aaa_realm") && json["aaa_realm"].is_string()) {
            config.aaa_realm = json["aaa_realm"].as_string();
        }
        if (json.contains("apn") && json["apn"].is_string()) {
            config.apn = json["apn"].as_string();
        }
        if (json.contains("eap_domain") && json["eap_domain"].is_string()) {
            config.eap_domain = json["eap_domain"].as_string();
        }
        if (json.contains("fd_conf_filename") && json["fd_conf_filename"].is_string()) {
            config.fd_conf_filename = json["fd_conf_filename"].as_string();
        }
        if (json.contains("access_interface") && json["access_interface"].is_string()) {
            config.access_interface = json["access_interface"].as_string();
        }
        if (json.contains("wlc_ip") && json["wlc_ip"].is_string()) {
            config.wlc_ip = json["wlc_ip"].as_string();
        }
        if (json.contains("acct_server_ip") && json["acct_server_ip"].is_string()) {
            config.acct_server_ip = json["acct_server_ip"].as_string();
        }
        if (json.contains("acct_server_port") && json["acct_server_port"].is_integer()) {
            config.acct_server_port = json["acct_server_port"].as_integer();
        }
        if (json.contains("max_active_sessions") && json["max_active_sessions"].is_integer()) {
            config.max_active_sessions = json["max_active_sessions"].as_integer();
        }
        if (json.contains("stats_log_interval_sec") && json["stats_log_interval_sec"].is_integer()) {
            config.stats_log_interval_sec = json["stats_log_interval_sec"].as_integer();
        }
    } else {
        std::cerr << "Failed to parse JSON config." << std::endl;
    }

    return config;
}
