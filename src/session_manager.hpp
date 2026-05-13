#ifndef SESSION_MANAGER_HPP
#define SESSION_MANAGER_HPP

#include "ue_session.hpp"
#include <unordered_map>
#include <memory>
#include <mutex>
#include <atomic>

class SessionManager {
public:
    SessionManager() : next_teid_(1) {}

    std::shared_ptr<UeSession> create_session(const std::string& mac_addr);
    std::shared_ptr<UeSession> get_session(const std::string& mac_addr);
    std::shared_ptr<UeSession> get_session_by_teid_c(uint32_t teid);
    void remove_session(const std::string& mac_addr);

    void increment_rejected();
    size_t get_active_sessions_count() const;
    void get_stats(size_t& active, uint64_t& total_conn, uint64_t& total_disconn, uint64_t& rejected) const;

private:
    std::unordered_map<std::string, std::shared_ptr<UeSession>> sessions_;
    mutable std::mutex mutex_;
    std::atomic<uint32_t> next_teid_;
    std::atomic<uint64_t> total_connections_{0};
    std::atomic<uint64_t> total_disconnections_{0};
    std::atomic<uint64_t> total_rejected_sessions_{0};
};

#endif // SESSION_MANAGER_HPP
