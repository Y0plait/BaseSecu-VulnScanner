"""
@file main.py
@brief Main orchestrator for vulnerability scanning across multiple machines

This script performs a comprehensive vulnerability assessment by:
1. Testing NVD API connectivity
2. Iterating through each machine in the inventory
3. Retrieving installed packages from each machine
4. Generating CPE (Common Platform Enumeration) identifiers using AI
5. Querying the NVD (National Vulnerability Database) for vulnerabilities
6. Generating JSON reports with vulnerability details and CVE links

@author Anton Moulin
@date 2025-12-24
@version 1.0

@details
The script uses:
- SSH to connect to remote Linux machines
- Google GenAI API to generate CPEs from package names
- NVD API to retrieve CVE data
- Local caching to optimize repeated runs
- Rate limiting to respect API quotas
"""

# System imports
import configparser
import os
import logging
from datetime import datetime
import time
import sys
import nvdlib
import argparse

# Custom helper imports
from src.matching import cpe_matcher
from src.reporting import output_formatter as fmt
from src.acquisition import machine_processor as mp
from src.reporting import vulnerability_checker as vc
from src.caching.constants import NVD_NIST_CPE_API_KEY, CACHE_DIR, DEFAULT_INVENTORY, API_REQUEST_DELAY

import json

# Configure logging
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_filename = os.path.join(log_dir, f"vulnerability_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.FileHandler(log_filename)
    ]
)

logger = logging.getLogger(__name__)


def flush_all_caches():
    """
    Remove all cached data including package caches, CPE caches, and vulnerability database.
    
    @details
    Flushes:
    - machines/cpe_cache.json (global CPE cache)
    - machines/{machine}/installed_packages.json (per-machine package lists)
    - machines/{machine}/vulnerability_report.json (generated reports)
    - db/vulnerability_cache.db (SQLite vulnerability cache)
    """
    items_flushed = []
    
    # Remove global CPE cache
    cpe_cache = os.path.join(CACHE_DIR, "cpe_cache.json")
    if os.path.exists(cpe_cache):
        os.remove(cpe_cache)
        items_flushed.append("Global CPE cache")
        logger.info(f"Flushed: {cpe_cache}")
    
    # Remove per-machine caches
    machines_dir = os.path.join(CACHE_DIR, "machines")
    if os.path.exists(machines_dir):
        for machine_dir in os.listdir(machines_dir):
            machine_path = os.path.join(machines_dir, machine_dir)
            if os.path.isdir(machine_path):
                # Remove installed_packages.json
                pkg_cache = os.path.join(machine_path, "installed_packages.json")
                if os.path.exists(pkg_cache):
                    os.remove(pkg_cache)
                    logger.info(f"Flushed: {pkg_cache}")
                
                # Remove vulnerability_report.json
                report = os.path.join(machine_path, "vulnerability_report.json")
                if os.path.exists(report):
                    os.remove(report)
                    logger.info(f"Flushed: {report}")
                
                if os.path.exists(pkg_cache) or os.path.exists(report):
                    items_flushed.append(f"Machine cache: {machine_dir}")
    
    # Remove SQLite vulnerability database
    db_file = os.path.join(CACHE_DIR, "vulnerability_cache.db")
    if os.path.exists(db_file):
        os.remove(db_file)
        items_flushed.append("SQLite vulnerability cache")
        logger.info(f"Flushed: {db_file}")
    
    if items_flushed:
        fmt.print_success(f"Cache flush completed. Removed: {', '.join(items_flushed)}")
        logger.info(f"Cache flush completed. Removed: {items_flushed}")
    else:
        fmt.print_info("No caches found to flush")
        logger.info("No caches found to flush")


def parse_arguments():
    """
    Parse command-line arguments for inventory file, cache flushing, and forced checks.
    
    @return argparse.Namespace Parsed arguments with attributes:
                               - inventory: Custom inventory file path
                               - flush_cache: Whether to flush all caches before scanning
                               - force_check: Whether to check all packages (not just new ones)
    
    @details
    Supported arguments:
    - --inventory FILE: Use custom inventory file (default: inventory.ini)
    - --flush-cache: Remove all cached data before scanning
    - --force-check: Check all packages even if no new ones detected (ignore cache)
    
    Examples:
    - python main.py --inventory custom_inventory.ini
    - python main.py --flush-cache
    - python main.py --force-check
    - python main.py --inventory custom.ini --flush-cache --force-check
    """
    parser = argparse.ArgumentParser(
        description="Vulnerability scanner for Linux machines with NVD integration"
    )
    parser.add_argument(
        "--inventory",
        type=str,
        default=DEFAULT_INVENTORY,
        help=f"Path to inventory file (default: {DEFAULT_INVENTORY})"
    )
    parser.add_argument(
        "--flush-cache",
        action="store_true",
        help="Flush all caches (CPE cache, package cache, vulnerability database) before scanning"
    )
    parser.add_argument(
        "--force-check",
        action="store_true",
        help="Check all installed packages for vulnerabilities, even if no new packages are detected"
    )
    return parser.parse_args()


def main():
    """
    Main entry point for the vulnerability scanner application.
    
    Orchestrates the complete vulnerability scanning workflow:
    1. Parse command-line arguments
    2. Load machine inventory from configuration file
    3. Process each machine to discover packages and generate CPEs
    4. Query NVD database for vulnerabilities
    5. Generate JSON reports with CVE details
    
    @return int Exit code (0 for success, 1 for errors)
    """
    
    # Parse command-line arguments
args = parse_arguments()
inventory_file = args.inventory

logger.info("="*70)
logger.info("Starting Vulnerability Scan")
logger.info(f"Log file: {log_filename}")
logger.info(f"Configuration file: {inventory_file}")

# Load inventory configuration
config = configparser.ConfigParser()
if not os.path.exists(inventory_file):
    fmt.print_error(f"Inventory file not found: {inventory_file}")
    logger.error(f"Inventory file not found: {inventory_file}")
    exit(1)

config.read(inventory_file)
logger.info(f"Configuration loaded from: {inventory_file}")

# Handle cache flushing if requested
if args.flush_cache:
    fmt.print_section("Flushing Caches")
    flush_all_caches()
    print()

# Initialize variable to hold installed packages
new_packages = ""
total_machines = len([m for m in config.keys() if m != "DEFAULT"])
machines_processed = 0
total_vulnerabilities = 0

logger.info(f"Total machines in inventory: {total_machines}")

# Test NVD API connectivity with a known vulnerable CPE
fmt.print_section("Testing NVD API Connectivity")
fmt.print_info("Testing direct connection to NVD API with a known CPE...")
logger.info("Testing NVD API connectivity (direct API call, no cache)")

test_cpe = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"  # Known vulnerable CPE (Log4Shell)
try:
    # Direct API call, bypassing cache
    test_vulns = nvdlib.searchCPE(cpeMatchString=test_cpe, key=NVD_NIST_CPE_API_KEY)
    vuln_count = len(test_vulns) if test_vulns else 0
    
    if vuln_count > 0:
        fmt.print_success(f"NVD API connectivity verified ({vuln_count} matches found)")
        logger.info(f"NVD API connectivity test successful: found {vuln_count} CPE matches for test CPE")
    else:
        fmt.print_warning("NVD API connectivity verified (no matches found for test CPE)")
        logger.info("NVD API connectivity test successful: no CPE matches for test CPE")
except Exception as e:
    fmt.print_error(f"NVD API connectivity test failed: {e}")
    logger.error(f"NVD API connectivity test failed: {e}")
    exit(1)
    
time.sleep(API_REQUEST_DELAY)  # Respect rate limit after test

# Iterate through each machine in the inventory
for machine in config.keys():

    # Skip default section
    if machine == "DEFAULT":
        continue

    # Determine machine type and get installed packages
    if config[machine]['type'] == 'linux':
        fmt.print_section(f"{machine} - {config[machine]['host']}")
        logger.info(f"Processing machine: {machine} ({config[machine]['host']})")
        
        installed_packages, new_packages = mp.process_machine_packages(config, machine)
        
        # Retrieve hardware information
        print()
        hardware_info = mp.process_machine_hardware(config, machine)
        
        # Use all packages if force-check is enabled, otherwise use only new packages
        packages_to_check = installed_packages if args.force_check else new_packages
        
        if not packages_to_check:
            fmt.print_warning(f"No packages to check" + (" (use --force-check to check all packages)" if not args.force_check else ""))
            logger.info(f"No packages to check on {machine}" + (" (force-check disabled)" if not args.force_check else ""))
        else:
            if args.force_check:
                fmt.print_info(f"Force-check enabled: checking all {len(packages_to_check)} installed packages")
                logger.info(f"Force-check enabled: checking all {len(packages_to_check)} installed packages on {machine}")
            
            # Generate CPEs for packages to check
            packages_cpes = mp.generate_cpes_for_packages(packages_to_check, machine, cpe_matcher)
            
            # Check vulnerabilities for packages
            print()
            vulnerabilities_found, machine_vulnerabilities = vc.check_vulnerabilities(
                packages_cpes, machine, NVD_NIST_CPE_API_KEY, API_REQUEST_DELAY
            )
        
        # Check hardware vulnerabilities if hardware info available
        if hardware_info and hardware_info.get('model_name'):
            print()
            hardware_cpes = mp.generate_cpes_for_hardware(hardware_info, machine, cpe_matcher)
            
            if hardware_cpes:
                # Check vulnerabilities for hardware CPEs
                hw_vulnerabilities_found, hw_machine_vulnerabilities = vc.check_vulnerabilities(
                    hardware_cpes, machine, NVD_NIST_CPE_API_KEY, API_REQUEST_DELAY, component_type="hardware"
                )
                
                # Merge hardware vulnerabilities with package vulnerabilities
                if hw_vulnerabilities_found:
                    machine_vulnerabilities.update(hw_machine_vulnerabilities)
                    vulnerabilities_found = vulnerabilities_found or hw_vulnerabilities_found
                    logger.info(f"Added {len(hw_machine_vulnerabilities)} hardware vulnerability entries to report")
        
        # Finalize report
        vuln_count = vc.finalize_machine_report(machine, vulnerabilities_found, machine_vulnerabilities)
        total_vulnerabilities += vuln_count
        machines_processed += 1

    elif config[machine]['type'] == 'windows':
        fmt.print_warning(f"Windows machines not yet supported")
        logger.warning(f"Skipping Windows machine {machine} - not yet supported")
        print()
        continue
    
    print()

# Print final summary
fmt.print_stats(total_machines, machines_processed, total_vulnerabilities)
logger.info("="*70)
logger.info(f"Vulnerability scan completed")
logger.info(f"Total machines processed: {machines_processed}/{total_machines}")
logger.info(f"Total vulnerabilities found: {total_vulnerabilities}")
logger.info(f"Log file saved to: {log_filename}")
logger.info("="*70)