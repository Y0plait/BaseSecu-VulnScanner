"""
@file machine_processor.py
@brief Machine-level processing module for package retrieval and CPE generation

This module handles all operations related to processing individual machines,
including:
- Retrieving installed packages from Linux machines via SSH
- Comparing with cached packages to identify new installations
- Generating CPE identifiers for newly installed packages using AI
- Managing CPE cache to avoid redundant generation

@author Aton Moulin
@date 2025-12-24
@version 1.0
"""

import os
import json
import logging

from src.caching.constants import CACHE_DIR
from src.acquisition import pkg_finder
from src.reporting import output_formatter as fmt

logger = logging.getLogger(__name__)


def process_machine_packages(config, machine):
    """
    Retrieve and process installed packages for a machine.
    
    Connects to a machine, retrieves all installed packages, compares them
    with previously cached packages, and identifies newly installed packages.
    
    @param config ConfigParser object containing machine configuration
    @param machine str Machine name from inventory
    
    @return tuple (installed_packages, new_packages)
            installed_packages list: All currently installed packages
            new_packages list: Packages not in the cache
            Returns ([], []) if machine type is not supported
    
    @details
    - Creates machine directory if it doesn't exist
    - Uses pkg_finder.get_installed_packages_linux() for SSH operations
    - Compares with cached data using pkg_finder.get_new_packages()
    - Updates package cache JSON file
    """
    if config[machine]['type'] != 'linux':
        return [], []
    
    # Ensure machine directory exists
    machine_dir = os.path.join(CACHE_DIR, "machines", machine)
    if not os.path.exists(machine_dir):
        os.makedirs(machine_dir)
        logger.debug(f"Created machine directory: {machine_dir}")
    
    fmt.print_info("Retrieving installed packages...")
    logger.debug(f"Retrieving installed packages from {machine}")
    installed_packages = pkg_finder.get_installed_packages_linux(config, machine)
    logger.info(f"Retrieved {len(installed_packages)} installed packages from {machine}")
    fmt.print_success(f"Found {len(installed_packages)} installed packages")
    
    # Get new packages only
    fmt.print_info("Checking for new packages...")
    logger.debug(f"Comparing packages with cached list for {machine}")
    new_packages = pkg_finder.get_new_packages(machine, installed_packages)
    logger.info(f"Found {len(new_packages)} new packages on {machine}")
    
    # Update cache with current packages
    pkg_cache_file = os.path.join(machine_dir, "installed_packages.json")
    with open(pkg_cache_file, "w") as pkg_file:
        pkg_file.write(json.dumps(installed_packages))
    logger.debug(f"Updated package cache for {machine}")
    
    if not new_packages:
        fmt.print_warning(f"No new packages to check. Skipping vulnerability analysis.")
        logger.info(f"No new packages on {machine}. Skipping CPE generation and vulnerability check.")
        return installed_packages, []
    
    fmt.print_success(f"Found {len(new_packages)} new packages to analyze")
    return installed_packages, new_packages


def generate_cpes_for_packages(new_packages, machine, cpe_matcher):
    """
    Generate Common Platform Enumeration (CPE) identifiers for packages.
    
    Uses Google GenAI API to intelligently map package names to CPE identifiers.
    Retrieves cached CPEs for previously processed packages to avoid redundant
    AI model calls.
    
    @param new_packages list Package names to generate CPEs for
    @param machine str Machine name for logging and file operations
    @param cpe_matcher module CPE matcher module with ask_for_cpe() function
    
    @return dict Dictionary mapping package names to their CPE lists
            Format: {package_name: [cpe_string_1, cpe_string_2, ...]}
    
    @details
    - Filters packages to only process those without cached CPEs
    - Calls AI model once with all packages (batch operation)
    - Parses AI response to extract valid CPE strings
    - Pairs CPEs 1:1 with packages
    - Caches generated CPEs for future runs
    - Retrieves previously cached CPEs for packages that have them
    """
    fmt.print_info("Generating CPEs for new packages...")
    logger.info(f"Starting CPE generation for {machine}")
    
    packages_cpes = {}
    packages_to_process = pkg_finder.get_packages_needing_cpe_generation(new_packages)
    logger.debug(f"Packages needing CPE generation: {len(packages_to_process)}")
    
    if not packages_to_process:
        fmt.print_info("All packages already have cached CPEs")
        logger.info(f"All {len(new_packages)} packages on {machine} have cached CPEs")
    else:
        model = "gemini-2.5-flash"
        fmt.print_info(f"Generating CPEs for {len(packages_to_process)} packages (calling AI model: {model})...")
        logger.info(f"Calling AI model ({model}) to generate CPEs for {len(packages_to_process)} packages on {machine}")
        
        # Call ask_for_cpe ONCE with all packages needing generation
        cpe_response = cpe_matcher.ask_for_cpe(packages_to_process, machine, model=model)
        
        # Parse the response to extract CPEs for each package
        cpes_from_response = [line.strip() for line in cpe_response.split('\n') if line.strip().startswith('cpe:')]
        logger.debug(f"Extracted {len(cpes_from_response)} CPEs from AI response")
        
        # Build a mapping of packages to their CPEs (with validation)
        valid_cpe_count = 0
        invalid_cpe_count = 0
        if cpes_from_response:
            for i, package in enumerate(packages_to_process):
                if i < len(cpes_from_response):
                    cpe = cpes_from_response[i].strip()
                    # Validate CPE format before storing
                    if cpe_matcher.validate_cpe_format(cpe):
                        packages_cpes[package] = [cpe]
                        valid_cpe_count += 1
                        logger.debug(f"Valid CPE for {package}: {cpe}")
                    else:
                        logger.warning(f"Invalid CPE format for {package}: {cpe}")
                        invalid_cpe_count += 1
                        packages_cpes[package] = []
                else:
                    packages_cpes[package] = []
        
        if invalid_cpe_count > 0:
            fmt.print_warning(f"Warning: {invalid_cpe_count} invalid CPE formats were rejected")
            logger.warning(f"Rejected {invalid_cpe_count} invalid CPEs for {machine}")
        
        # Cache all generated CPEs at once
        if packages_cpes:
            pkg_finder.cache_cpes(packages_cpes)
            fmt.print_success(f"CPEs generated and cached for {len(packages_cpes)} packages ({valid_cpe_count} valid)")
            logger.info(f"CPEs generated and cached for {len(packages_cpes)} packages on {machine} ({valid_cpe_count} valid, {invalid_cpe_count} invalid)")
    
    # Add cached CPEs for packages that were already cached
    for package in new_packages:
        if package not in packages_cpes:
            cached_cpes = pkg_finder.get_cached_cpes(package)
            if cached_cpes:
                packages_cpes[package] = cached_cpes
    
    return packages_cpes
