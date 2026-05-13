#include "twag_core.hpp"
#include <iostream>
#include <string>
#include <cstring>

int main(int argc, char** argv) {
    std::cout << "Starting TWAG" << std::endl;

    std::string config_file = "twag_config.json";

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config_file = argv[++i];
        } else if (argv[i][0] != '-') {
            config_file = argv[i];
        } else {
            std::cerr << "Usage: " << argv[0] << " [-c <config_file>] | [<config_file>]" << std::endl;
            return 1;
        }
    }

    TwagCore twag(config_file);
    if (!twag.initialize()) {
        std::cerr << "Failed to initialize TWAG Core." << std::endl;
        return 1;
    }

    twag.run();

    std::cout << "TWAG Exiting." << std::endl;
    return 0;
}

