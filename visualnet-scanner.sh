#!/bin/bash

# Define required binaries
DEPENDENCIES=("nmap" "dot")
FORMATTER="./nmap-formatter"

# 1. Check for system-wide dependencies
for cmd in "${DEPENDENCIES[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: Required command '$cmd' is not installed."
        exit 1
    fi
done

# 2. Check for the local nmap-formatter binary
if [ ! -f "$FORMATTER" ]; then
    echo "Error: '$FORMATTER' not found in the current directory."
    exit 1
elif [ ! -x "$FORMATTER" ]; then
    echo "Error: '$FORMATTER' is found but is not executable. Run 'chmod +x nmap-formatter'."
    exit 1
fi

# 3. Get the target address
if [ -z "$1" ]; then
    read -p "Enter the network address to scan: " TARGET
else
    TARGET=$1
fi

if [ -z "$TARGET" ]; then
    echo "Error: No network address provided."
    exit 1
fi

# 4. Get output file (optional, default to test.svg)
if [ -z "$2" ]; then
    OUTPUT_FILE="test.svg"
else
    OUTPUT_FILE=$2
fi

# 5. Execution
echo "[1/2] Starting Nmap scan on $TARGET..."
if nmap -T4 -F "$TARGET" -oX output.xml > /dev/null 2>nmap_errors.log; then
    echo "      Scan complete."
else
    echo "      Error during Nmap scan. Check nmap_errors.log."
    exit 1
fi

echo "[2/2] Generating SVG visualization..."
if "$FORMATTER" dot output.xml | dot -Tsvg > "$OUTPUT_FILE"; then
    echo "      Success! Map saved as '$OUTPUT_FILE'."
else
    echo "      Error generating visualization."
    exit 1
fi
