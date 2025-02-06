#!/bin/bash

# Set Ghidra installation directory
export GHIDRA_INSTALL_DIR=/opt/ghidra_11.2.1

# Clean old build artifacts
rm -rf build
rm -rf bin

# Run build with debug output
./gradlew clean build --info --stacktrace
