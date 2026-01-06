#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define required binaries
DEPENDENCIES=("nmap" "dot")
FORMATTER="$SCRIPT_DIR/nmap-formatter"

# 1. Check for system-wide dependencies
for cmd in "${DEPENDENCIES[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: Required command '$cmd' is not installed." >&2
        exit 1
    fi
done

# 2. Check for the local nmap-formatter binary
if [ ! -f "$FORMATTER" ]; then
    echo "Error: '$FORMATTER' not found in the project root." >&2
    exit 1
elif [ ! -x "$FORMATTER" ]; then
    echo "Error: '$FORMATTER' is found but is not executable. Run 'chmod +x nmap-formatter'." >&2
    exit 1
fi

# 3. Get the target address
if [ -z "$1" ]; then
    read -p "Enter the network address to scan: " TARGET
else
    TARGET=$1
fi

if [ -z "$TARGET" ]; then
    echo "Error: No network address provided." >&2
    exit 1
fi

# 4. Get output file (optional, default to network_topology.svg)
if [ -z "$2" ]; then
    OUTPUT_FILE="network_topology.svg"
else
    OUTPUT_FILE=$2
fi

# 5. Create temporary directory for scan
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

cd "$TEMP_DIR"

# 6. Execution (all logging to stderr so stdout is clean SVG output)
echo "[1/3] Starting Nmap scan on $TARGET..." >&2
if nmap -T4 -F "$TARGET" -oX output.xml > /dev/null 2>&1; then
    echo "[2/3] Nmap scan complete. Converting to SVG..." >&2
else
    echo "Error: Nmap scan failed for $TARGET" >&2
    exit 1
fi

# 7. Convert XML to SVG using nmap-formatter and graphviz
echo "[3/3] Generating SVG visualization..." >&2
if "$FORMATTER" dot output.xml | dot -Tsvg -o "$OUTPUT_FILE"; then
    # Output the SVG file content to stdout ONLY (no extra messages)
    if [ -f "$OUTPUT_FILE" ]; then
        echo "✓ SVG generated successfully" >&2
        cat "$OUTPUT_FILE"
    else
        echo "Error: SVG file was not generated" >&2
        exit 1
    fi
else
    echo "Error: Failed to convert XML to SVG" >&2
    exit 1
fi
