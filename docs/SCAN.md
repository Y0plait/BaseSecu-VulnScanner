# Network Scanner Setup Guide

## Overview

The `visualnet-scanner.sh` script is a bash-based network scanning utility that combines **Nmap** for network discovery with **nmap-formatter** to generate visual SVG network diagrams. This tool allows you to scan networks and automatically generate graphical representations of discovered hosts and services.

## Features

- **Network Scanning**: Uses Nmap to perform fast network scans
- **XML Output**: Converts Nmap results to structured XML format
- **Visual Mapping**: Generates SVG diagrams of the network topology
- **Dependency Validation**: Automatically checks for required dependencies before execution

## Prerequisites

Before running the scanner, ensure you have the following installed:

### System Requirements

- **Nmap**: Network mapping and port scanning utility
- **Graphviz**: Graph visualization software (specifically the `dot` command)
- **nmap-formatter**: Binary formatter for converting Nmap output to various formats

## Installation

### Step 1: Install Nmap

#### macOS
```bash
brew install nmap
```

#### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install nmap
```

#### Linux (Fedora/RHEL)
```bash
sudo dnf install nmap
```

### Step 2: Install Graphviz

#### macOS
```bash
brew install graphviz
```

#### Linux (Debian/Ubuntu)
```bash
sudo apt-get install graphviz
```

#### Linux (Fedora/RHEL)
```bash
sudo dnf install graphviz
```

### Step 3: Install nmap-formatter

The `nmap-formatter` tool is available through multiple installation methods. Choose the one that best fits your environment:

#### Option A: Go Install (Recommended for Go Users)

Requires Go 1.18 or later to be installed on your system.

```bash
go install github.com/vdjagilev/nmap-formatter/v3@latest
```

The binary will be installed to your Go workspace (typically `$GOPATH/bin` or `~/go/bin`).

#### Option B: Download Pre-compiled Binary

Download the appropriate binary for your system from the [nmap-formatter releases page](https://github.com/vdjagilev/nmap-formatter/releases):

```bash
# For Linux x86_64
VERSION=v3.0.0
curl https://github.com/vdjagilev/nmap-formatter/releases/download/$VERSION/nmap-formatter-linux-amd64.tar.gz --output nmap-formatter.tar.gz -L
tar -xzvf nmap-formatter.tar.gz

# For macOS (Intel or Apple Silicon, check the releases page for your architecture)
VERSION=v3.0.0
curl https://github.com/vdjagilev/nmap-formatter/releases/download/$VERSION/nmap-formatter-darwin-amd64.tar.gz --output nmap-formatter.tar.gz -L
tar -xzvf nmap-formatter.tar.gz
```

After extraction, place the `nmap-formatter` binary in the project directory:

```bash
chmod +x nmap-formatter
mv nmap-formatter ./
```

#### Option C: Compile from Source

If you have Go installed:

```bash
git clone git@github.com:vdjagilev/nmap-formatter.git
cd nmap-formatter
go mod tidy
go build
cp nmap-formatter /path/to/your/project/
```

#### Option D: Docker

If you prefer containerization:

```bash
docker run -v /path/to/xml/file.xml:/opt/file.xml ghcr.io/vdjagilev/nmap-formatter:latest json /opt/file.xml
```

## Usage

### Basic Syntax

```bash
./visualnet-scanner.sh [TARGET_NETWORK]
```

### Parameters

- `TARGET_NETWORK` (optional): The network address to scan (e.g., `192.168.1.0/24`, `10.0.0.1`)
  - If not provided, you will be prompted to enter it interactively

### Examples

#### Interactive Mode
```bash
./visualnet-scanner.sh
# You will be prompted to enter the network address
```

#### Direct Scan
```bash
./visualnet-scanner.sh 192.168.1.0/24
```

#### Single Host Scan
```bash
./visualnet-scanner.sh 192.168.1.100
```

## How It Works

The script performs the following steps:

1. **Dependency Check**: Verifies that `nmap`, `dot`, and the `./nmap-formatter` binary are available and executable
2. **Target Input**: Prompts for network address if not provided as an argument
3. **Nmap Scan**: Executes a fast Nmap scan (`-T4 -F` flags) on the target network, saving output to `output.xml`
4. **Visualization**: Pipes the Nmap output through `nmap-formatter` to convert to DOT format, then to Graphviz's `dot` command to generate an SVG image
5. **Output**: Produces `test.svg` containing a visual representation of the network

### Output Files

- **output.xml**: Raw Nmap scan results in XML format
- **nmap_errors.log**: Error log from the Nmap scan (if any errors occur)
- **test.svg**: SVG visualization of the network topology

## Troubleshooting

### Error: "Required command 'nmap' is not installed"
**Solution**: Install Nmap using the appropriate package manager for your system (see Installation section above).

### Error: "Required command 'dot' is not installed"
**Solution**: Install Graphviz, which includes the `dot` command.

### Error: "'./nmap-formatter' not found in the current directory"
**Solution**: Ensure the `nmap-formatter` binary is in the same directory as the script. If using Go install, you may need to copy the binary from your Go workspace to the project directory.

### Error: "'./nmap-formatter' is found but is not executable"
**Solution**: Make the binary executable:
```bash
chmod +x nmap-formatter
```

### Error during Nmap scan
**Solution**: Check `nmap_errors.log` for details. Common issues include:
- Insufficient permissions (may need `sudo` for privileged scans)
- Network unreachable
- Invalid network address format

## Advanced Usage

### Running with Elevated Privileges

For comprehensive network scanning (including OS detection and service version detection), you may need elevated privileges:

```bash
sudo ./visualnet-scanner.sh 192.168.1.0/24
```

### Customizing Nmap Parameters

To modify scan speed or options, edit the script and change the Nmap command line:

```bash
# Current (fast scan)
nmap -T4 -F "$TARGET" -oX output.xml

# More thorough scan
nmap -sV -sC -A "$TARGET" -oX output.xml
```

## Integration with Python Project

The scanner can be integrated with the Python vulnerability scanning system:

```bash
# Scan network
./visualnet-scanner.sh 192.168.1.0/24

# Identified hosts can then be added to inventory.ini
# and processed by the main.py vulnerability scanner
```

## Security Considerations

- **Permissions**: Only run network scans on networks you own or have explicit permission to scan
- **Credentials**: Never commit nmap-formatter binaries with security concerns to version control
- **Network Impact**: Fast scans (`-T4 -F`) are less intrusive; adjust timing if network is sensitive

## References

- [Nmap Official Documentation](https://nmap.org/book/)
- [nmap-formatter GitHub Repository](https://github.com/vdjagilev/nmap-formatter)
- [nmap-formatter Wiki](https://github.com/vdjagilev/nmap-formatter/wiki)
- [Graphviz Documentation](https://graphviz.org/documentation/)

## License

This script documentation is provided as part of the network vulnerability assessment project.
