#ifndef DATA_PLANE_HPP
#define DATA_PLANE_HPP

#include <string>
#include <netinet/in.h>
#include "event_loop.hpp"
#include "config_manager.hpp"

class TwagCore;

class DataPlane {
public:
    DataPlane(EventLoop* event_loop, const TwagConfig& config, TwagCore* core);
    ~DataPlane();

    bool initialize();

private:
    void handle_access_rx(uint32_t events);

    EventLoop* event_loop_;
    TwagConfig config_;
    TwagCore* core_;
    int raw_fd_;
};

#endif // DATA_PLANE_HPP