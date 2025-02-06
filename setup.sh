#!/bin/bash

# Default Ghidra installation directory
GHIDRA_DIR="/opt/ghidra_11.2.1"

# Create local.properties
cat > local.properties << EOL
GHIDRA_INSTALL_DIR=$GHIDRA_DIR
EOL

echo "Created local.properties with GHIDRA_INSTALL_DIR=$GHIDRA_DIR"
echo "Edit local.properties if your Ghidra installation is in a different location."

# Make gradlew executable
chmod +x gradlew
