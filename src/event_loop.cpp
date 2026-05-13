#include "event_loop.hpp"
#include <unistd.h>
#include <iostream>
#include <cstring>

EventLoop::EventLoop() : epoll_fd_(-1), running_(false) {}

EventLoop::~EventLoop() {
    if (epoll_fd_ >= 0) {
        close(epoll_fd_);
    }
}

bool EventLoop::initialize() {
    epoll_fd_ = epoll_create1(0);
    if (epoll_fd_ < 0) {
        std::cerr << "Failed to create epoll fd: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

bool EventLoop::add_fd(int fd, uint32_t events, EventHandler handler) {
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
        std::cerr << "epoll_ctl ADD failed for fd " << fd << ": " << strerror(errno) << std::endl;
        return false;
    }
    handlers_[fd] = std::move(handler);
    return true;
}

bool EventLoop::modify_fd(int fd, uint32_t events) {
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev) < 0) {
        std::cerr << "epoll_ctl MOD failed for fd " << fd << ": " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

bool EventLoop::remove_fd(int fd) {
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr) < 0) {
        std::cerr << "epoll_ctl DEL failed for fd " << fd << ": " << strerror(errno) << std::endl;
        return false;
    }
    handlers_.erase(fd);
    return true;
}

void EventLoop::add_timer(uint32_t milliseconds, std::function<void()> callback) {
    auto expire_time = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
    timers_.insert({expire_time, std::move(callback)});
}

void EventLoop::run() {
    running_ = true;
    const int MAX_EVENTS = 64;
    struct epoll_event events[MAX_EVENTS];

    while (running_) {
        int timeout_ms = 1000;
        if (!timers_.empty()) {
            auto now = std::chrono::steady_clock::now();
            auto first_expire = timers_.begin()->first;
            if (now >= first_expire) {
                timeout_ms = 0;
            } else {
                auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(first_expire - now).count();
                timeout_ms = std::min((int)diff, 1000);
            }
        }

        int n = epoll_wait(epoll_fd_, events, MAX_EVENTS, timeout_ms);
        if (n < 0) {
            if (errno == EINTR) continue;
            std::cerr << "epoll_wait failed: " << strerror(errno) << std::endl;
            break;
        }

        auto now = std::chrono::steady_clock::now();
        while (!timers_.empty() && timers_.begin()->first <= now) {
            auto cb = timers_.begin()->second;
            timers_.erase(timers_.begin());
            cb();
            now = std::chrono::steady_clock::now();
        }

        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            auto it = handlers_.find(fd);
            if (it != handlers_.end()) {
                it->second(events[i].events);
            }
        }
    }
}

void EventLoop::stop() {
    running_ = false;
}
