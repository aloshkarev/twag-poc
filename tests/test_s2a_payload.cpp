#include <gtest/gtest.h>
#include <cstring>
#include <arpa/inet.h>

extern "C" {
#include <gtp_ies.h>
#include <gtp_messages.h>
#include <gtp_messages_encoder.h>
#include <gtp_messages_decoder.h>
}

TEST(S2aPayloadTest, EncodeDecodeCreateSessionRequest) {
    create_sess_req_t req;
    memset(&req, 0, sizeof(req));
    
    // Header
    req.header.gtpc.version = 2;
    req.header.gtpc.teid_flag = 0;
    req.header.gtpc.message_type = CREATE_SESS_REQ;
    req.header.teid.no_teid.seq = 1;
    
    // IMSI
    req.imsi.header.type = GTP_IE_IMSI;
    req.imsi.header.len = 8;
    req.imsi.header.instance = 0;
    req.imsi.imsi_number_digits = 0x0911012143658709ULL;
    
    // RAT Type
    req.rat_type.header.type = GTP_IE_RAT_TYPE;
    req.rat_type.header.len = 1;
    req.rat_type.header.instance = 0;
    req.rat_type.rat_type = 3; // WLAN
    
    uint8_t buffer[2048];
    int encoded_len = encode_create_sess_req(&req, buffer);
    ASSERT_GT(encoded_len, 0);

    create_sess_req_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int decoded_len = decode_create_sess_req(buffer, &decoded);
    
    ASSERT_GT(decoded_len, 0);
    EXPECT_EQ(decoded.header.gtpc.message_type, CREATE_SESS_REQ);
    EXPECT_EQ(decoded.imsi.header.type, GTP_IE_IMSI);
    EXPECT_EQ(decoded.rat_type.rat_type, 3);
}