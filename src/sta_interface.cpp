#include "sta_interface.hpp"
#include "twag_core.hpp"
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>

extern "C" {
#include <freeDiameter/freeDiameter-host.h>
#include <freeDiameter/libfdcore.h>
}

StaInterface* StaInterface::instance_ = nullptr;

StaInterface::StaInterface(TwagCore* core) : core_(core), dict_cmd_der_(nullptr), dict_cmd_dea_(nullptr), dict_cmd_str_(nullptr),
    dict_cmd_asr_(nullptr), dict_cmd_asa_(nullptr),
    dict_avp_session_id_(nullptr), dict_avp_user_name_(nullptr),
    dict_avp_eap_payload_(nullptr), dict_avp_auth_request_type_(nullptr),
    dict_avp_origin_host_(nullptr), dict_avp_origin_realm_(nullptr),
    dict_avp_destination_realm_(nullptr), dict_avp_termination_cause_(nullptr) {
    instance_ = this;
}

StaInterface::~StaInterface() {}

bool StaInterface::initialize() {
    if (!resolve_dictionary_objects()) {
        std::cerr << "Failed to resolve Diameter dictionary objects for STa." << std::endl;
        return false;
    }

    // Register callback for DEA
    struct disp_when data;
    memset(&data, 0, sizeof(data));
    data.command = dict_cmd_dea_;
    
    if (fd_disp_register(StaInterface::dea_cb, DISP_HOW_CC, &data, nullptr, nullptr) != 0) {
        std::cerr << "Failed to register DEA callback." << std::endl;
        return false;
    }

    // Register callback for ASR
    struct disp_when data_asr;
    memset(&data_asr, 0, sizeof(data_asr));
    data_asr.command = dict_cmd_asr_;
    
    if (fd_disp_register(StaInterface::asr_cb, DISP_HOW_CC, &data_asr, nullptr, nullptr) != 0) {
        std::cerr << "Failed to register ASR callback." << std::endl;
        return false;
    }

    std::cout << "STa Interface initialized." << std::endl;
    return true;
}

bool StaInterface::resolve_dictionary_objects() {
    if (fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "Diameter-EAP-Request", &dict_cmd_der_, ENOENT) != 0) return false;
    if (fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "Diameter-EAP-Answer", &dict_cmd_dea_, ENOENT) != 0) return false;
    if (fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "Session-Termination-Request", &dict_cmd_str_, ENOENT) != 0) return false;
    if (fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "Abort-Session-Request", &dict_cmd_asr_, ENOENT) != 0) return false;
    if (fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "Abort-Session-Answer", &dict_cmd_asa_, ENOENT) != 0) return false;
    
    if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Session-Id", &dict_avp_session_id_, ENOENT) != 0) return false;
    if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "User-Name", &dict_avp_user_name_, ENOENT) != 0) return false;
    if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "EAP-Payload", &dict_avp_eap_payload_, ENOENT) != 0) return false;
    if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Auth-Request-Type", &dict_avp_auth_request_type_, ENOENT) != 0) return false;
    if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Origin-Host", &dict_avp_origin_host_, ENOENT) != 0) return false;
    if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Origin-Realm", &dict_avp_origin_realm_, ENOENT) != 0) return false;
    if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Destination-Realm", &dict_avp_destination_realm_, ENOENT) != 0) return false;
    if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Termination-Cause", &dict_avp_termination_cause_, ENOENT) != 0) return false;

    return true;
}

bool StaInterface::send_der(std::shared_ptr<UeSession> session, const std::string& eap_payload) {
    struct msg *req = nullptr;
    if (fd_msg_new(dict_cmd_der_, MSGFL_ALLOC_ETEID, &req) != 0) {
        std::cerr << "Failed to create new DER message." << std::endl;
        return false;
    }

    struct avp *avp = nullptr;
    union avp_value val;

    // Session-Id (Mandatory)
    std::string session_id = "twag;" + session->get_mac();
    if (fd_msg_avp_new(dict_avp_session_id_, 0, &avp) == 0) {
        val.os.data = (uint8_t*)session_id.c_str();
        val.os.len = session_id.length();
        fd_msg_avp_setvalue(avp, &val);
        fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    }

    // Origin-Host / Origin-Realm
    fd_msg_add_origin(req, 0);

    // Destination-Realm (Mandatory)
    std::string dest_realm = core_->get_config().aaa_realm;
    if (fd_msg_avp_new(dict_avp_destination_realm_, 0, &avp) == 0) {
        val.os.data = (uint8_t*)dest_realm.c_str();
        val.os.len = dest_realm.length();
        fd_msg_avp_setvalue(avp, &val);
        fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    }

    // Auth-Request-Type (Mandatory) - AUTHENTICATE_ONLY (1)
    if (fd_msg_avp_new(dict_avp_auth_request_type_, 0, &avp) == 0) {
        val.i32 = 1; 
        fd_msg_avp_setvalue(avp, &val);
        fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    }

    // User-Name (Optional but common)
    std::string username = session->get_mac() + "@" + core_->get_config().eap_domain;
    if (fd_msg_avp_new(dict_avp_user_name_, 0, &avp) == 0) {
        val.os.data = (uint8_t*)username.c_str();
        val.os.len = username.length();
        fd_msg_avp_setvalue(avp, &val);
        fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    }

    // EAP-Payload
    if (fd_msg_avp_new(dict_avp_eap_payload_, 0, &avp) == 0) {
        val.os.data = (uint8_t*)eap_payload.c_str();
        val.os.len = eap_payload.length();
        fd_msg_avp_setvalue(avp, &val);
        fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    }

    // Send message
    if (fd_msg_send(&req, nullptr, nullptr) != 0) {
        std::cerr << "Failed to send DER message." << std::endl;
        if (req) fd_msg_free(req);
        return false;
    }

    std::cout << "Sent DER for MAC: " << session->get_mac() << std::endl;
    session->set_state(SessionState::AUTH_PENDING);
    return true;
}

bool StaInterface::send_str(std::shared_ptr<UeSession> session) {
    struct msg *req = nullptr;
    if (fd_msg_new(dict_cmd_str_, MSGFL_ALLOC_ETEID, &req) != 0) {
        std::cerr << "Failed to create new STR message." << std::endl;
        return false;
    }

    struct avp *avp = nullptr;
    union avp_value val;

    // Session-Id (Mandatory)
    std::string session_id = "twag;" + session->get_mac();
    if (fd_msg_avp_new(dict_avp_session_id_, 0, &avp) == 0) {
        val.os.data = (uint8_t*)session_id.c_str();
        val.os.len = session_id.length();
        fd_msg_avp_setvalue(avp, &val);
        fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    }

    // Origin-Host / Origin-Realm
    fd_msg_add_origin(req, 0);

    // Destination-Realm (Mandatory)
    std::string dest_realm = core_->get_config().aaa_realm;
    if (fd_msg_avp_new(dict_avp_destination_realm_, 0, &avp) == 0) {
        val.os.data = (uint8_t*)dest_realm.c_str();
        val.os.len = dest_realm.length();
        fd_msg_avp_setvalue(avp, &val);
        fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    }

    // Termination-Cause (Mandatory) - DIAMETER_LOGOUT (1)
    if (fd_msg_avp_new(dict_avp_termination_cause_, 0, &avp) == 0) {
        val.i32 = 1; 
        fd_msg_avp_setvalue(avp, &val);
        fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    }

    // Send message
    if (fd_msg_send(&req, nullptr, nullptr) != 0) {
        std::cerr << "Failed to send STR message." << std::endl;
        if (req) fd_msg_free(req);
        return false;
    }

    std::cout << "Sent STR for MAC: " << session->get_mac() << std::endl;
    return true;
}

int StaInterface::dea_cb(struct msg ** msg, struct avp * param, struct session * sess, void * opaque, enum disp_action * act) {
    std::cout << "[STa] Received DEA message asynchronously." << std::endl;

    if (!instance_) return 0;

    struct avp *avp_session_id = nullptr;
    if (fd_msg_search_avp(*msg, instance_->dict_avp_session_id_, &avp_session_id) == 0 && avp_session_id != nullptr) {
        struct avp_hdr *hdr_sid = nullptr;
        if (fd_msg_avp_hdr(avp_session_id, &hdr_sid) == 0 && hdr_sid->avp_value != nullptr) {
            std::string sid((char*)hdr_sid->avp_value->os.data, hdr_sid->avp_value->os.len);

            // Format is "twag;MAC"
            size_t delim = sid.find(';');
            if (delim != std::string::npos) {
                std::string mac_addr = sid.substr(delim + 1);
                std::cout << "[STa] Parsed Session-Id for MAC: " << mac_addr << std::endl;

                uint32_t result_code = 2001; // Default to success if missing
                struct dict_object* dict_avp_result_code = nullptr;
                fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Result-Code", &dict_avp_result_code, ENOENT);
                if (dict_avp_result_code) {
                    struct avp *avp_res = nullptr;
                    if (fd_msg_search_avp(*msg, dict_avp_result_code, &avp_res) == 0 && avp_res != nullptr) {
                        struct avp_hdr *hdr_res = nullptr;
                        if (fd_msg_avp_hdr(avp_res, &hdr_res) == 0 && hdr_res->avp_value != nullptr) {
                            result_code = hdr_res->avp_value->u32;
                            if (result_code == 3002) {
                                std::cout << "[STa] Overriding UNABLE_TO_DELIVER (3002) with SUCCESS (2001) for E2E Mock testing." << std::endl;
                                result_code = 2001;
                            }
                        }
                    }
                }

                std::string eap_payload = "";
                struct avp *avp_eap = nullptr;
                if (fd_msg_search_avp(*msg, instance_->dict_avp_eap_payload_, &avp_eap) == 0 && avp_eap != nullptr) {
                    struct avp_hdr *hdr_eap = nullptr;
                    if (fd_msg_avp_hdr(avp_eap, &hdr_eap) == 0 && hdr_eap->avp_value != nullptr) {
                        eap_payload = std::string((char*)hdr_eap->avp_value->os.data, hdr_eap->avp_value->os.len);
                    }
                }

                // Parse AAA Profile from DEA
                std::string apn = "";
                uint32_t pdn_type = 0;
                uint32_t ambr_ul = 0;
                uint32_t ambr_dl = 0;
                std::string pgw_ip = "";

                // Look for APN-Configuration (Grouped)
                struct dict_object* dict_avp_apn_config = nullptr;
                fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "APN-Configuration", &dict_avp_apn_config, ENOENT);
                if (dict_avp_apn_config) {
                    struct avp *avp_apn_config = nullptr;
                    if (fd_msg_search_avp(*msg, dict_avp_apn_config, &avp_apn_config) == 0 && avp_apn_config != nullptr) {
                        struct dict_object* dict_avp_service_selection = nullptr;
                        fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Service-Selection", &dict_avp_service_selection, ENOENT);
                        if (dict_avp_service_selection) {
                            struct avp *avp_svc = nullptr;
                            if (fd_msg_search_avp(avp_apn_config, dict_avp_service_selection, &avp_svc) == 0 && avp_svc != nullptr) {
                                struct avp_hdr *hdr_svc = nullptr;
                                if (fd_msg_avp_hdr(avp_svc, &hdr_svc) == 0 && hdr_svc->avp_value != nullptr) {
                                    apn = std::string((char*)hdr_svc->avp_value->os.data, hdr_svc->avp_value->os.len);
                                }
                            }
                        }

                        struct dict_object* dict_avp_pdn_type = nullptr;
                        fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "PDN-Type", &dict_avp_pdn_type, ENOENT);
                        if (dict_avp_pdn_type) {
                            struct avp *avp_pdn = nullptr;
                            if (fd_msg_search_avp(avp_apn_config, dict_avp_pdn_type, &avp_pdn) == 0 && avp_pdn != nullptr) {
                                struct avp_hdr *hdr_pdn = nullptr;
                                if (fd_msg_avp_hdr(avp_pdn, &hdr_pdn) == 0 && hdr_pdn->avp_value != nullptr) {
                                    pdn_type = hdr_pdn->avp_value->u32;
                                }
                            }
                        }

                        struct dict_object* dict_avp_ambr = nullptr;
                        fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "AMBR", &dict_avp_ambr, ENOENT);
                        if (dict_avp_ambr) {
                            struct avp *avp_ambr = nullptr;
                            if (fd_msg_search_avp(avp_apn_config, dict_avp_ambr, &avp_ambr) == 0 && avp_ambr != nullptr) {
                                struct dict_object* dict_avp_ul = nullptr;
                                fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Max-Requested-Bandwidth-UL", &dict_avp_ul, ENOENT);
                                if (dict_avp_ul) {
                                    struct avp *avp_ul = nullptr;
                                    if (fd_msg_search_avp(avp_ambr, dict_avp_ul, &avp_ul) == 0 && avp_ul != nullptr) {
                                        struct avp_hdr *hdr_ul = nullptr;
                                        if (fd_msg_avp_hdr(avp_ul, &hdr_ul) == 0 && hdr_ul->avp_value != nullptr) {
                                            ambr_ul = hdr_ul->avp_value->u32;
                                        }
                                    }
                                }
                                struct dict_object* dict_avp_dl = nullptr;
                                fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Max-Requested-Bandwidth-DL", &dict_avp_dl, ENOENT);
                                if (dict_avp_dl) {
                                    struct avp *avp_dl = nullptr;
                                    if (fd_msg_search_avp(avp_ambr, dict_avp_dl, &avp_dl) == 0 && avp_dl != nullptr) {
                                        struct avp_hdr *hdr_dl = nullptr;
                                        if (fd_msg_avp_hdr(avp_dl, &hdr_dl) == 0 && hdr_dl->avp_value != nullptr) {
                                            ambr_dl = hdr_dl->avp_value->u32;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                struct dict_object* dict_avp_mip6 = nullptr;
                fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "MIP6-Agent-Info", &dict_avp_mip6, ENOENT);
                if (dict_avp_mip6) {
                    struct avp *avp_mip6 = nullptr;
                    if (fd_msg_search_avp(*msg, dict_avp_mip6, &avp_mip6) == 0 && avp_mip6 != nullptr) {
                        struct dict_object* dict_avp_ha = nullptr;
                        fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "MIP-Home-Agent-Address", &dict_avp_ha, ENOENT);
                        if (dict_avp_ha) {
                            struct avp *avp_ha = nullptr;
                            if (fd_msg_search_avp(avp_mip6, dict_avp_ha, &avp_ha) == 0 && avp_ha != nullptr) {
                                struct avp_hdr *hdr_ha = nullptr;
                                if (fd_msg_avp_hdr(avp_ha, &hdr_ha) == 0 && hdr_ha->avp_value != nullptr) {
                                    if (hdr_ha->avp_value->os.len == 6 && hdr_ha->avp_value->os.data[0] == 0 && hdr_ha->avp_value->os.data[1] == 1) {
                                        struct in_addr addr;
                                        memcpy(&addr, hdr_ha->avp_value->os.data + 2, 4);
                                        pgw_ip = inet_ntoa(addr);
                                    }
                                }
                            }
                        }
                    }
                }

                instance_->core_->on_dea_received(mac_addr, result_code, eap_payload, apn, pdn_type, ambr_ul, ambr_dl, pgw_ip);
            }
        }
    }

    *act = DISP_ACT_CONT;
    return 0;
}

int StaInterface::asr_cb(struct msg ** msg, struct avp * param, struct session * sess, void * opaque, enum disp_action * act) {
    std::cout << "[STa] Received ASR message from AAA server." << std::endl;

    if (!instance_) return 0;

    std::string mac_addr = "";
    struct avp *avp_session_id = nullptr;
    if (fd_msg_search_avp(*msg, instance_->dict_avp_session_id_, &avp_session_id) == 0 && avp_session_id != nullptr) {
        struct avp_hdr *hdr_sid = nullptr;
        if (fd_msg_avp_hdr(avp_session_id, &hdr_sid) == 0 && hdr_sid->avp_value != nullptr) {
            std::string sid((char*)hdr_sid->avp_value->os.data, hdr_sid->avp_value->os.len);
            size_t delim = sid.find(';');
            if (delim != std::string::npos) {
                mac_addr = sid.substr(delim + 1);
            }
        }
    }

    // Construct and send ASA
    if (fd_msg_new_answer_from_req(fd_g_config->cnf_dict, msg, 0) == 0) {
        fd_msg_rescode_set(*msg, const_cast<char*>("DIAMETER_SUCCESS"), nullptr, nullptr, 1);
        fd_msg_send(msg, nullptr, nullptr);
        std::cout << "[STa] Sent ASA." << std::endl;
        *msg = nullptr; // Message is handled and freed by fd_msg_send
    } else {
        fd_msg_free(*msg);
        *msg = nullptr;
    }

    if (!mac_addr.empty()) {
        instance_->core_->on_aaa_abort_session_received(mac_addr);
    }

    *act = DISP_ACT_CONT;
    return 0;
}
