# Trusted WLAN Access Gateway (TWAG)

## Project Overview

This project is a Proof-of-Concept (PoC) and Minimum Viable Product (MVP) for a **Trusted WLAN Access Gateway (TWAG)**. It is an asynchronous C++ service designed to act as a bridge between trusted Wi-Fi networks (Access Points/Wireless LAN Controllers) and a mobile operator's core network (EPC/5GC). 

The gateway implements an end-to-end asynchronous flow for user equipment (UE) authentication and user data routing at the Linux kernel level.

### Key Components:
*   **TWAN (RADIUS) Frontend:** An async UDP server (port 1812) that handles `Access-Request` and `Accounting-Request` messages, parses RADIUS TLV and EAP-Identity to extract the IMSI, and supports Multi-Round EAP (EAP-AKA/SIM).
*   **STa Interface (Diameter):** Integrates with `freeDiameter` to communicate with AAA servers. It encapsulates RADIUS EAP payloads into Diameter requests (DER/DEA).
*   **S2a Interface (GTPv2-C & GTP-U):** 
    *   **Control Plane:** Uses `libgtpv2c` to establish sessions with the Packet Data Network Gateway (PGW) via `Create Session Request/Response`.
    *   **User Plane:** Uses `libgtpnl` (Netlink) to dynamically create `gtp0` interfaces in the Linux kernel and manages L3 IP routing for UE traffic.

### Main Technologies:
*   **Language:** C++17
*   **Build System:** CMake
*   **Networking:** `epoll` for non-blocking I/O
*   **Libraries:** `freeDiameter`, `libgtpv2c`, `libgtpnl`, `yajson` (JSON parsing)
*   **Testing:** GoogleTest

## Building and Running

### Prerequisites
*   A Linux environment (requires kernel-level GTP support for user plane routing).
*   Standard C++ build tools (GCC/Clang, Make) and CMake.

### Build Instructions
A helper script is provided to configure and build the project using CMake:
```bash
./build.sh
```
This will create a `build` directory and output the `twag` executable and `twag_tests` binaries.

### Running the Gateway
The gateway can be executed directly from the build directory. It accepts an optional configuration file:
```bash
./build/twag [-c path/to/config.json]
```
If no configuration file is provided, it defaults to looking for `twag_config.json`.

### Testing
To run the full end-to-end Mobile Network Operator (MNO) simulation, which brings up mock AAA and PGW servers and creates the `gtp0` kernel interface, use the provided script. **Note:** This requires root privileges.
```bash
sudo ./test_mno.sh
```

Unit and integration tests can be run using the compiled test binary:
```bash
./build/twag_tests
```

## Development Conventions

*   **C++ Standard:** The project strictly enforces C++17 (`CMAKE_CXX_STANDARD 17`).
*   **Asynchronous Design:** The core architecture relies on an event loop (`EventLoop`) backed by `epoll`. All network operations and timers should integrate with this non-blocking design.
*   **Testing:** New features and state machine changes should be accompanied by corresponding GoogleTest cases.
*   **External Dependencies:** The project relies heavily on third-party C libraries (`freeDiameter`, `libgtpnl`, `libgtpv2c`). Care must be taken when interfacing C++ structures with C APIs (e.g., managing memory, avoiding namespace collisions via `extern "C"`).