#!/bin/bash
set -e

echo "==============================="
echo "Building TWAG MNO PoC Project"
echo "==============================="

mkdir -p build
cd build

echo "Configuring CMake..."
cmake ..

echo "Compiling with $(nproc) cores..."
make -j$(nproc)

echo "==============================="
echo "Build completed successfully!"
echo "Binaries are located in the build/ directory:"
echo " - build/twag"
echo " - build/twag_tests"
echo "==============================="
