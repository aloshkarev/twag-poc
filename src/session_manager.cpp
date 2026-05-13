#include "session_manager.hpp"

std::shared_ptr<UeSession> SessionManager::create_session(const std::string& mac_addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto session = std::make_shared<UeSession>(mac_addr);
    session->gtp_teid_c_ = next_teid_.fetch_add(1);
    session->gtp_teid_u_ = next_teid_.fetch_add(1);
    sessions_[mac_addr] = session;
    total_connections_++;
    return session;
}

std::shared_ptr<UeSession> SessionManager::get_session(const std::string& mac_addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(mac_addr);
    if (it != sessions_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<UeSession> SessionManager::get_session_by_teid_c(uint32_t teid) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& pair : sessions_) {
        if (pair.second->gtp_teid_c_ == teid) {
            return pair.second;
        }
    }
    return nullptr;
}

void SessionManager::remove_session(const std::string& mac_addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (sessions_.erase(mac_addr) > 0) {
        total_disconnections_++;
    }
}

void SessionManager::increment_rejected() {
    total_rejected_sessions_++;
}

size_t SessionManager::get_active_sessions_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

void SessionManager::get_stats(size_t& active, uint64_t& total_conn, uint64_t& total_disconn, uint64_t& rejected) const {
    std::lock_guard<std::mutex> lock(mutex_);
    active = sessions_.size();
    total_conn = total_connections_.load();
    total_disconn = total_disconnections_.load();
    rejected = total_rejected_sessions_.load();
}
