"""
@file network_visualizer.py
@brief Network visualization using nmap-formatter and visualnet-scanner.sh

Generates SVG network topology diagrams for each machine's network segment
using the visualnet-scanner.sh script and nmap-formatter.

@author Anton Moulin
@date 2025-12-24
@version 1.0

@details
Features:
- Generates network topology SVGs for each scanned host's network
- Integrates with existing visualnet-scanner.sh script
- Caches SVG files for report inclusion
- Converts SVG to base64 for embedding in HTML reports
- Handles nmap-formatter execution and error cases
"""

import os
import subprocess
import logging
import base64
from pathlib import Path

from src.caching.constants import CACHE_DIR

logger = logging.getLogger(__name__)


def create_fallback_network_svg(host_address, machine_name):
    """
    Create a fallback SVG showing network information when real scan is unavailable.
    
    @param host_address str IP address or hostname
    @param machine_name str Machine name
    
    @return str SVG content as string
    
    @details
    Generates a simple informational SVG showing the scanned host when
    actual network scan fails due to missing dependencies (nmap, nmap-formatter, graphviz)
    """
    svg_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<svg width="800" height="300" xmlns="http://www.w3.org/2000/svg">
    <!-- Background -->
    <rect width="800" height="300" fill="#f8f9fa" stroke="#ddd" stroke-width="1"/>
    
    <!-- Header -->
    <rect width="800" height="60" fill="#667eea"/>
    <text x="400" y="40" font-size="24" font-weight="bold" text-anchor="middle" fill="white">
        Network Information - {machine_name}
    </text>
    
    <!-- Host Information -->
    <g transform="translate(50, 100)">
        <!-- Host box -->
        <rect x="0" y="0" width="700" height="150" fill="white" stroke="#667eea" stroke-width="2" rx="5"/>
        
        <!-- Host icon -->
        <circle cx="60" cy="50" r="35" fill="#667eea" stroke="#fff" stroke-width="2"/>
        <text x="60" y="58" font-size="32" text-anchor="middle" fill="white">🖥</text>
        
        <!-- Host details -->
        <text x="120" y="35" font-size="18" font-weight="bold" fill="#333">Host: {machine_name}</text>
        <text x="120" y="65" font-size="16" fill="#666">IP Address: {host_address}</text>
        <text x="120" y="95" font-size="14" fill="#999">Network scanning requires: nmap, graphviz, nmap-formatter</text>
        <text x="120" y="120" font-size="13" fill="#999">See NETWORK_SCANNER_SETUP.md for installation instructions</text>
    </g>
    
    <!-- Footer note -->
    <text x="400" y="280" font-size="12" text-anchor="middle" fill="#999">
        This is a placeholder diagram. Run nmap manually for detailed network topology.
    </text>
</svg>"""
    return svg_content


def generate_network_svg_for_host(host_address, machine_name):
    """
    Generate SVG network topology diagram for a specific host using visualnet-scanner.
    
    @param host_address str IP address or network address (e.g., '192.168.10.66', '192.168.10.0/24')
    @param machine_name str Machine name for file naming and logging
    
    @return str Path to generated SVG file, or None if generation failed
    
    @details
    Executes visualnet-scanner.sh to scan the network and generate SVG topology.
    Output is saved to cache/machines/{machine_name}/network_topology.svg
    
    The script expects visualnet-scanner.sh to be in the project root directory.
    """
    try:
        # Determine the scan target - use the host address
        scan_target = host_address
        
        # Create output directory for this machine
        machine_dir = os.path.join(CACHE_DIR, "machines", machine_name)
        os.makedirs(machine_dir, exist_ok=True)
        
        # Define output SVG file path
        svg_output = os.path.join(machine_dir, "network_topology.svg")
        
        # Get the project root directory (go up from src/reporting/ to project root)
        # __file__ → /path/src/reporting/network_visualizer.py
        # dirname → /path/src/reporting
        # dirname → /path/src
        # dirname → /path (project root)
        current_file = os.path.abspath(__file__)  # Full path to this file
        src_dir = os.path.dirname(current_file)   # src/reporting/
        src_parent = os.path.dirname(src_dir)     # src/
        project_root = os.path.dirname(src_parent) # project root
        
        scanner_script = os.path.join(project_root, "visualnet-scanner.sh")
        
        # Check if scanner script exists
        if not os.path.exists(scanner_script):
            logger.warning(f"visualnet-scanner.sh not found at {scanner_script}")
            return None
        
        # Check if script is executable
        if not os.access(scanner_script, os.X_OK):
            logger.warning(f"visualnet-scanner.sh is not executable: {scanner_script}")
            return None
        
        logger.info(f"Generating network SVG for {machine_name} ({scan_target})...")
        
        # Execute the scanner script
        # Syntax: ./visualnet-scanner.sh <target> <output.svg>
        result = subprocess.run(
            [scanner_script, scan_target, svg_output],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout for network scan
        )
        
        # Check if execution was successful
        if result.returncode != 0:
            logger.error(f"Network scan failed for {machine_name}: {result.stderr}")
            # Try to create a fallback informational SVG
            logger.info(f"Creating fallback network information SVG for {machine_name}")
            svg_fallback = create_fallback_network_svg(host_address, machine_name)
            if svg_fallback:
                with open(svg_output, 'w') as f:
                    f.write(svg_fallback)
                logger.info(f"Created fallback SVG for {machine_name}")
                return svg_output
            return None
        
        # Verify output file was created
        if not os.path.exists(svg_output):
            logger.error(f"SVG file was not created for {machine_name}")
            # Try fallback
            svg_fallback = create_fallback_network_svg(host_address, machine_name)
            if svg_fallback:
                with open(svg_output, 'w') as f:
                    f.write(svg_fallback)
                return svg_output
            return None
        
        # Check if SVG file has content
        file_size = os.path.getsize(svg_output)
        if file_size == 0:
            logger.error(f"Generated SVG file is empty for {machine_name}")
            # Try fallback
            svg_fallback = create_fallback_network_svg(host_address, machine_name)
            if svg_fallback:
                with open(svg_output, 'w') as f:
                    f.write(svg_fallback)
                return svg_output
            return None
        
        logger.info(f"Successfully generated network SVG for {machine_name} ({file_size} bytes)")
        return svg_output
        
    except subprocess.TimeoutExpired:
        logger.error(f"Network scan timed out for {machine_name}")
        return None
    except Exception as e:
        logger.error(f"Error generating network SVG for {machine_name}: {e}")
        return None


def svg_to_base64(svg_file_path):
    """
    Convert SVG file to base64 encoding for embedding in HTML.
    
    @param svg_file_path str Path to SVG file
    
    @return str Base64 encoded SVG content, or None if file not found/readable
    
    @details
    Converts SVG file to base64 for direct embedding in HTML via data URI.
    This allows the SVG to be included without external file dependencies.
    """
    try:
        if not os.path.exists(svg_file_path):
            logger.warning(f"SVG file not found: {svg_file_path}")
            return None
        
        with open(svg_file_path, 'rb') as f:
            svg_content = f.read()
        
        # Encode to base64
        encoded = base64.b64encode(svg_content).decode('utf-8')
        logger.debug(f"Converted SVG to base64: {svg_file_path}")
        return encoded
        
    except Exception as e:
        logger.error(f"Error converting SVG to base64: {e}")
        return None


def read_svg_content(svg_file_path):
    """
    Read SVG file content as string for direct inclusion in HTML.
    
    @param svg_file_path str Path to SVG file
    
    @return str SVG content, or None if file not found/readable
    
    @details
    Reads the SVG file as text and returns the content.
    This allows inline SVG embedding without data URI encoding.
    """
    try:
        if not os.path.exists(svg_file_path):
            logger.warning(f"SVG file not found: {svg_file_path}")
            return None
        
        with open(svg_file_path, 'r') as f:
            svg_content = f.read()
        
        logger.debug(f"Read SVG file: {svg_file_path}")
        return svg_content
        
    except Exception as e:
        logger.error(f"Error reading SVG file: {e}")
        return None


def generate_network_visualizations(machines_config):
    """
    Generate network visualizations for all machines in the inventory.
    
    @param machines_config dict Machine configuration from inventory
                                 {machine_name: {'host': ip, 'user': user, ...}}
    
    @return dict Network visualization data
                 {machine_name: {
                     'svg_path': 'path/to/file.svg',
                     'svg_content': '<svg>...</svg>',
                     'generated': True/False
                 }}
    
    @details
    Iterates through all Linux machines in the inventory and generates
    network topology SVGs for their respective networks.
    Returns both file paths and inline SVG content for flexible inclusion in reports.
    """
    network_visualizations = {}
    
    logger.info(f"Generating network visualizations for {len(machines_config)} machines...")
    
    for machine_name, machine_config in machines_config.items():
        if machine_config.get('type') != 'linux':
            logger.debug(f"Skipping {machine_name}: not a Linux machine")
            continue
        
        host_address = machine_config.get('host')
        if not host_address:
            logger.warning(f"No host address found for {machine_name}")
            continue
        
        # Generate SVG for this host
        svg_path = generate_network_svg_for_host(host_address, machine_name)
        
        network_visualizations[machine_name] = {
            'svg_path': svg_path,
            'svg_content': None,
            'generated': False
        }
        
        if svg_path:
            # Read SVG content for embedding
            svg_content = read_svg_content(svg_path)
            network_visualizations[machine_name]['svg_content'] = svg_content
            network_visualizations[machine_name]['generated'] = True
            logger.info(f"Network visualization ready for {machine_name}")
        else:
            logger.warning(f"Failed to generate network visualization for {machine_name}")
    
    logger.info(f"Network visualization generation complete: {sum(1 for v in network_visualizations.values() if v['generated'])} successful")
    return network_visualizations
