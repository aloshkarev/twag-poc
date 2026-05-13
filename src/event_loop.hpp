#ifndef EVENT_LOOP_HPP
#define EVENT_LOOP_HPP

#include <functional>
#include <map>
#include <sys/epoll.h>
#include <chrono>

class EventLoop {
public:
    using EventHandler = std::function<void(uint32_t events)>;

    EventLoop();
    ~EventLoop();

    bool initialize();
    void run();
    void stop();

    bool add_fd(int fd, uint32_t events, EventHandler handler);
    bool modify_fd(int fd, uint32_t events);
    bool remove_fd(int fd);

    void add_timer(uint32_t milliseconds, std::function<void()> callback);

private:
    using TimePoint = std::chrono::steady_clock::time_point;
    int epoll_fd_;
    bool running_;
    std::map<int, EventHandler> handlers_;
    std::multimap<TimePoint, std::function<void()>> timers_;
};

#endif // EVENT_LOOP_HPP
