#include <gtest/gtest.h>
#include "session_manager.hpp"

TEST(SessionManagerTest, CreateAndRetrieveSession) {
    SessionManager manager;
    auto session = manager.create_session("AA:BB:CC:DD:EE:FF");
    
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->get_mac(), "AA:BB:CC:DD:EE:FF");
    EXPECT_EQ(session->get_state(), SessionState::INIT);

    auto retrieved = manager.get_session("AA:BB:CC:DD:EE:FF");
    ASSERT_NE(retrieved, nullptr);
    EXPECT_EQ(retrieved, session);
}

TEST(SessionManagerTest, StateTransitions) {
    SessionManager manager;
    auto session = manager.create_session("11:22:33:44:55:66");

    session->set_state(SessionState::AUTH_PENDING);
    EXPECT_EQ(session->get_state(), SessionState::AUTH_PENDING);

    session->set_state(SessionState::GTP_CREATE_PENDING);
    EXPECT_EQ(session->get_state(), SessionState::GTP_CREATE_PENDING);

    session->set_state(SessionState::CONNECTED);
    EXPECT_EQ(session->get_state(), SessionState::CONNECTED);
}

TEST(SessionManagerTest, SessionRemoval) {
    SessionManager manager;
    manager.create_session("00:11:22:33:44:55");
    EXPECT_NE(manager.get_session("00:11:22:33:44:55"), nullptr);

    manager.remove_session("00:11:22:33:44:55");
    EXPECT_EQ(manager.get_session("00:11:22:33:44:55"), nullptr);
}