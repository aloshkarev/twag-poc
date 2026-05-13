#ifndef STA_INTERFACE_HPP
#define STA_INTERFACE_HPP

#include "ue_session.hpp"
#include <memory>
#include <string>

class TwagCore;

extern "C" {
#include <freeDiameter/freeDiameter-host.h>
#include <freeDiameter/libfdcore.h>
}

class StaInterface {
public:
    StaInterface(TwagCore* core);
    ~StaInterface();

    bool initialize();
    
    // Construct and send DER (Diameter EAP Request)
    bool send_der(std::shared_ptr<UeSession> session, const std::string& eap_payload);

    // Construct and send STR (Session-Termination-Request)
    bool send_str(std::shared_ptr<UeSession> session);

    // Callback to register with freeDiameter for DEA (Diameter EAP Answer)
    static int dea_cb(struct msg ** msg, struct avp * param, struct session * sess, void * opaque, enum disp_action * act);

    // Callback for ASR (Abort-Session-Request)
    static int asr_cb(struct msg ** msg, struct avp * param, struct session * sess, void * opaque, enum disp_action * act);

private:
    bool resolve_dictionary_objects();

    TwagCore* core_;
    // Since fd_disp_register takes a static callback, we need a way to route it back to the instance.
    // For now, we can keep a static pointer.
    static StaInterface* instance_;

    // Dictionary objects
    struct dict_object* dict_cmd_der_;
    struct dict_object* dict_cmd_dea_;
    struct dict_object* dict_cmd_str_;
    struct dict_object* dict_cmd_asr_;
    struct dict_object* dict_cmd_asa_;
    struct dict_object* dict_avp_session_id_;
    struct dict_object* dict_avp_user_name_;
    struct dict_object* dict_avp_eap_payload_;
    struct dict_object* dict_avp_auth_request_type_;
    struct dict_object* dict_avp_origin_host_;
    struct dict_object* dict_avp_origin_realm_;
    struct dict_object* dict_avp_destination_realm_;
    struct dict_object* dict_avp_termination_cause_;
};

#endif // STA_INTERFACE_HPP
