"""
@file pkg_finder.py
@brief Package retrieval, caching, and CPE matching module

Handles SSH-based package retrieval from remote Linux machines with intelligent
caching and sanitization. Implements two-level caching:
1. Per-machine package cache (detects new/removed packages)
2. Global CPE cache (avoids redundant AI/API queries)

Supports multiple Linux distributions:
- Debian/Ubuntu (apt package manager)
- Red Hat/Fedora/AlmaLinux (dnf package manager)
- Alpine Linux (apk package manager)

@author Anton Moulin
@date 2025-12-24
@version 1.0

@details
**Caching Strategy:**

Package Cache (per-machine):
- File: machines/{machine}/installed_packages.json
- Contains: Serialized list of all currently installed packages
- Purpose: Delta detection - identifies newly installed/removed packages
- Benefits: Avoids regenerating CPEs for unchanged packages

CPE Cache (global):
- File: machines/cpe_cache.json
- Contains: {package_name: [{"cpe": "cpe:...", "valid": true/false}, ...]}
- Purpose: Caches AI-generated CPEs and API-verified CPEs
- Benefits: Avoids regenerating CPEs across machine scans
- Validity Tracking: Marks 404 CPEs as invalid to skip API queries

**Sanitization Logic:**

Package managers output different formats:
- apt: "package/distribution version architecture [status]"
- dnf: "package.arch version repo"
- apk: "package-version"

Sanitization handles:
1. Detect format by checking for "/" (apt) or " " (dnf/apk)
2. Extract package name (before "/" or space)
3. Remove metadata like "[installed]"
4. Remove version information
5. Validate result is non-empty and starts with alphanumeric or dash

**SSH Connection:**

Requires SSH credentials from inventory.ini:
- host: IP address or hostname
- user: SSH username
- password: SSH password (or key-based auth via paramiko)

Auto-detects OS via /etc/os-release to choose package manager.
Gracefully handles connection failures and unknown distributions.
"""

import paramiko
import json
import os
import logging

from constants import CACHE_DIR

logger = logging.getLogger(__name__)

# Ensure cache directory exists
if not os.path.exists(CACHE_DIR):
    os.makedirs(CACHE_DIR)

# Function to get installed packages from a Linux machine
def get_installed_packages_linux(loaded_config, machine_inventory_name) -> list:
    """
    Retrieve installed packages from a remote Linux machine via SSH.
    
    @param loaded_config dict Configuration dictionary (typically from ConfigParser)
    @param machine_inventory_name str Machine name/identifier from inventory
    
    @return list List of sanitized package names (all empty results filtered out)
    
    @details
    **Connection Process:**
    1. Parse machine configuration (host, username, password)
    2. Establish SSH connection using paramiko
    3. Query /etc/os-release to detect OS type
    4. Select appropriate package manager:
       - apt for Debian/Ubuntu
       - dnf for RedHat/Fedora/AlmaLinux
       - apk for Alpine Linux
    5. Execute package listing command
    6. Parse and sanitize output
    7. Close SSH connection
    
    **Sanitization:**
    The sanitization pipeline handles the format differences:
    @code
    apt format:    package-name/distribution 1.2.3-4ubuntu1
    dnf format:    package-name.arch 2.1.0-1.fc40
    @endcode
    
    Both formats are converted to just the package name.
    
    **Error Handling:**
    - Connection failures: Logged and returns empty list
    - Unknown OS: Logged as warning, returns empty list
    - SSH command errors: Logged as debug
    
    @note
    Configuration must include keys for the machine:
    - config[machine_inventory_name]['host']
    - config[machine_inventory_name]['user']
    - config[machine_inventory_name]['password']
    
    @throws paramiko.ssh_exception.* Exceptions are caught and logged, not re-raised
    """
    config = loaded_config
    machine = machine_inventory_name

    linux_client = paramiko.SSHClient()
    linux_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    os_id = ""

    try:
        logger.debug(f"Connecting to {machine} ({config[machine]['host']})")
        linux_client.connect(config[machine]['host'], username=config[machine]['user'], password=config[machine]['password'])
        stdin, stdout, stderr = linux_client.exec_command('cat /etc/os-release | grep -i id')
        logger.debug(f"Connected to {machine}, retrieving OS information")
        os_id = stdout.read().decode().strip()
        logger.debug(f"OS information for {machine}: {os_id}")
    except Exception as e:
        logger.error(f"Connection error to {machine} ({config[machine]['host']}): {e}")
        return []

    if "almalinux" in os_id.lower() or "fedora" in os_id.lower() or "rhel" in os_id.lower():
        logger.info(f"{machine} is based on Red Hat Enterprise Linux or Fedora")
        package_manager = "dnf"
    elif "ubuntu" in os_id.lower() or "debian" in os_id.lower():
        logger.info(f"{machine} is based on Debian")
        package_manager = "apt"
    elif "alpine" in os_id.lower():
        logger.info(f"{machine} is based on Alpine Linux")
        package_manager = "apk"
    else:
        logger.warning(f"Could not determine the package manager for {machine}")
        package_manager = None
    
    logger.debug(f"Using package manager: {package_manager or 'None'}")
    if package_manager:
        logger.debug(f"Retrieving installed packages from {machine} using {package_manager}")
        stdin, stdout, stderr = linux_client.exec_command(f'{package_manager} list --installed')
        installed_packages = stdout.read().decode()
    else:
        logger.warning(f"Skipping package listing for {machine} due to unknown package manager")
        installed_packages = ""
    
    linux_client.close()
    logger.debug(f"Closed SSH connection to {machine}")

    # Sanitize package list - PRESERVE VERSION INFORMATION
    sanitized_packages = []
    for pkg in installed_packages.splitlines():
        pkg = pkg.strip()
        # Skip empty lines and lines with "Listing"
        if not pkg or "listing" in pkg.lower():
            continue
        
        # Handle apt output format: package/distribution version architecture
        # Format: package-name/distro version architecture [status]
        # We want: package-name-version
        if "/" in pkg:
            # Split on "/" to get package/distro part
            pkg_part = pkg.split("/")[0].strip()
            # Then extract version from the rest after distribution
            rest = pkg.split()[1:] if " " in pkg else []
            version = rest[0].strip() if rest else ""
            if version and version not in ("[installed]", "[upgradable]"):
                pkg = f"{pkg_part}-{version}"
            else:
                pkg = pkg_part
        elif " " in pkg:
            # For dnf format: package.arch version status
            # Format: package-name.architecture version [installonly]
            parts = pkg.split()
            if len(parts) >= 2:
                pkg_name = parts[0]
                version = parts[1]
                # Remove architecture suffix (.x86_64, .noarch, etc.)
                if "." in pkg_name and not pkg_name.startswith("."):
                    pkg_name = pkg_name.rsplit(".", 1)[0]
                # Combine package name with version
                pkg = f"{pkg_name}-{version}"
            else:
                pkg = parts[0] if parts else ""
        
        # Remove any remaining metadata like [installed], [upgradable], etc.
        if "[" in pkg:
            pkg = pkg.split("[")[0].strip()
        
        # Clean up any trailing dashes or spaces
        pkg = pkg.rstrip("-").strip()
        
        # Only add non-empty results that look like valid package-version strings
        if pkg and (pkg[0].isalnum() or pkg[0] in ('-', '_')):
            sanitized_packages.append(pkg)
            logger.debug(f"Added package: {pkg}")
    
    logger.info(f"Sanitized {len(sanitized_packages)} packages from raw output ({len(installed_packages.splitlines())} lines)")
    
    return sanitized_packages

def get_new_packages(machine_inventory_name, current_installed_packages) -> list:
    """
    Detect packages that are newly installed since last scan.
    
    @param machine_inventory_name str Machine identifier
    @param current_installed_packages list Current packages from get_installed_packages_linux()
    
    @return list Packages not present in previous cached state
    
    @details
    **Delta Detection Algorithm:**
    1. Load previous package list from machines/{machine}/installed_packages.json
    2. Create sets of current and previous packages
    3. Compute set difference: current - previous = new packages
    4. Also compute previous - current = removed packages (logged for awareness)
    5. Return only new packages (unchanged packages are ignored)
    
    **Caching Behavior:**
    - First run: No cache exists, all packages returned as "new"
    - Subsequent runs: Only truly new packages returned
    - Cache file: machines/{machine}/installed_packages.json
    
    **Benefits:**
    - Avoids regenerating CPEs for packages that are unchanged
    - Detects both added and removed packages (logs removed for awareness)
    - Gracefully handles missing cache (first-time setup)
    
    **File Format:**
    Cache file is JSON array:
    @code
    ["package1", "package2", "package3", ...]
    @endcode
    
    @note
    After calling this function, machine_processor.py should update the cache
    by calling save_package_cache(machine, current_installed_packages)
    """
    machine = machine_inventory_name
    new_packages = []
    removed_packages = []
    
    try:
        machine_cache_path = os.path.join(CACHE_DIR, "machines", machine, "installed_packages.json")
        with open(machine_cache_path, "r") as pkg_file:
            previous_installed_packages = json.loads(pkg_file.read())
        logger.debug(f"Loaded cached packages for {machine}")
    except FileNotFoundError:
        logger.info(f"No cached packages found for {machine}. All packages will be checked.")
        return current_installed_packages

    current_set = set(current_installed_packages)
    previous_set = set(previous_installed_packages)
    
    new_packages = list(current_set - previous_set)
    removed_packages = list(previous_set - current_set)

    if new_packages:
        logger.info(f"New packages installed on {machine}: {new_packages}")
    
    if removed_packages:
        logger.info(f"Packages removed from {machine}: {removed_packages}")

    if not new_packages and not removed_packages:
        logger.info(f"No changes in installed packages on {machine}")
    
    return new_packages

def get_cached_cpes(package_name) -> list:
    """
    Retrieve cached CPEs for a package, filtering out invalid (404) entries.
    
    @param package_name str Package name to look up in cache
    
    @return list List of valid CPE strings for the package (empty if not cached)
    
    @details
    **Cache Lookup:**
    1. Check if machines/cpe_cache.json exists
    2. Load JSON and find package entry
    3. Filter entries by validity flag
    4. Return only valid CPEs (valid: true)
    
    **Validity Tracking:**
    CPE cache format:
    @code
    {
        "package_name": [
            {"cpe": "cpe:2.3:a:...", "valid": true},
            {"cpe": "cpe:2.3:a:...", "valid": false}
        ],
        ...
    }
    @endcode
    
    Invalid CPEs (valid: false) are caused by NVD API 404 responses and indicate
    that the package/version combination doesn't exist in vulnerability databases.
    These are skipped to avoid redundant API queries.
    
    **Cache Miss Behavior:**
    - Cache file doesn't exist: Returns empty list
    - Package not in cache: Returns empty list
    - All entries marked invalid: Returns empty list (triggers regeneration)
    
    **Backward Compatibility:**
    Old cache format (strings instead of objects) is handled by treating
    missing "valid" key as valid=true.
    
    @note
    Returned CPEs are ready to pass to vulnerability_checker.check_vulnerabilities()
    """
    cache_file = os.path.join(CACHE_DIR, "cpe_cache.json")
    
    if not os.path.exists(cache_file):
        logger.debug(f"CPE cache file does not exist for package {package_name}")
        return []
    
    try:
        with open(cache_file, "r") as f:
            cache_data = json.loads(f.read())
            cpe_entries = cache_data.get(package_name, [])
            
            # Filter to only valid CPEs
            valid_cpes = []
            for entry in cpe_entries:
                if isinstance(entry, dict):
                    # New format: {"cpe": "...", "valid": true/false}
                    if entry.get("valid", True):  # Default to True for backward compatibility
                        valid_cpes.append(entry.get("cpe", ""))
                else:
                    # Old format: just the CPE string
                    valid_cpes.append(entry)
            
            if valid_cpes:
                logger.debug(f"Found {len(valid_cpes)} valid cached CPEs for {package_name}")
            return valid_cpes
    except Exception as e:
        logger.error(f"Error reading CPE cache for {package_name}: {e}")
        return []

def cache_cpes(packages_cpes_dict):
    """
    Cache newly generated CPEs to the global cache file.
    
    @param packages_cpes_dict dict Mapping of {package_name: [cpe_string, ...]}
    
    @details
    **Caching Process:**
    1. Load existing cache (machines/cpe_cache.json)
    2. Merge new CPEs, wrapping each in validity object: {"cpe": "...", "valid": true}
    3. Write updated cache back to file
    
    **Cache Merging:**
    New CPEs are merged with existing cache entries. If a package already exists
    in cache, it will be updated (not appended to).
    
    **File Format:**
    Output is pretty-printed JSON for readability:
    @code
    {
        "curl": [
            {"cpe": "cpe:2.3:a:curl:curl:7.85.0:*:*:*:*:*:*:*", "valid": true},
            {"cpe": "cpe:2.3:a:curl:curl:7.85.1:*:*:*:*:*:*:*", "valid": true}
        ],
        "openssl": [...]
    }
    @endcode
    
    **Error Handling:**
    - Cache file missing: Creates new cache
    - Corrupted JSON: Logs error and starts fresh
    - File write errors: Logged but doesn't raise (attempts best effort)
    
    **Storage Location:**
    machines/cpe_cache.json (shared across all machine scans)
    
    @note
    This function should be called after ask_for_cpe() returns successfully
    """
    cache_file = os.path.join(CACHE_DIR, "cpe_cache.json")
    
    # Load existing cache
    try:
        with open(cache_file, "r") as f:
            cache_data = json.loads(f.read())
        logger.debug(f"Loaded existing CPE cache from {cache_file}")
    except FileNotFoundError:
        cache_data = {}
        logger.debug(f"CPE cache file {cache_file} does not exist, creating new cache")
    except Exception as e:
        logger.error(f"Error reading existing CPE cache: {e}")
        cache_data = {}
    
    # Update cache with new entries (wrap CPEs in objects with validity flag)
    for package, cpe_list in packages_cpes_dict.items():
        cache_data[package] = [{"cpe": cpe, "valid": True} for cpe in cpe_list]
    logger.debug(f"Added {len(packages_cpes_dict)} packages to CPE cache")
    
    # Write updated cache
    try:
        with open(cache_file, "w") as f:
            f.write(json.dumps(cache_data, indent=2))
        logger.info(f"CPE cache updated with {len(packages_cpes_dict)} packages")
    except Exception as e:
        logger.error(f"Error writing CPE cache: {e}")


def mark_cpe_invalid(cpe_string):
    """
    Mark a CPE as invalid (404 response from NVD API) in the cache.
    
    @param cpe_string str CPE identifier to mark as invalid
    
    @details
    **Why Mark CPEs Invalid?**
    When NVD API returns HTTP 404 for a CPE, it means the CPE doesn't exist
    in their database (invalid combination of vendor/product/version).
    
    Marking as invalid:
    - Prevents redundant API calls for non-existent packages
    - Clearly distinguishes from temporary errors (429 rate limit, 503 unavailable)
    - Maintains cache size by not querying known-invalid CPEs
    
    **Implementation:**
    1. Load machines/cpe_cache.json
    2. Find the CPE in any package's entry
    3. Set valid: false
    4. Write cache back to disk
    
    **Error Handling:**
    - Cache file not found: Silently returns (nothing to invalidate)
    - Corrupted JSON: Logs error and returns
    - Write failures: Logged but doesn't raise
    
    **Called From:**
    vulnerability_checker.py when NVD API returns 404 status code.
    
    @note
    404 errors are different from 429/503 errors and should not cause
    retries or backoff - they indicate the CPE is genuinely invalid.
    """
    cache_file = os.path.join(CACHE_DIR, "cpe_cache.json")
    
    try:
        with open(cache_file, "r") as f:
            cache_data = json.loads(f.read())
    except FileNotFoundError:
        cache_data = {}
    except Exception as e:
        logger.error(f"Error reading CPE cache for invalidation: {e}")
        return
    
    # Find and mark the CPE as invalid
    for package, cpe_list in cache_data.items():
        if isinstance(cpe_list, list):
            for cpe_entry in cpe_list:
                if isinstance(cpe_entry, dict) and cpe_entry.get("cpe") == cpe_string:
                    cpe_entry["valid"] = False
                    logger.info(f"Marked CPE as invalid: {cpe_string}")
    
    # Write updated cache
    try:
        with open(cache_file, "w") as f:
            f.write(json.dumps(cache_data, indent=2))
    except Exception as e:
        logger.error(f"Error writing CPE cache during invalidation: {e}")

def get_packages_needing_cpe_generation(packages) -> list:
    """
    Filter packages to identify those without cached CPEs.
    
    @param packages list List of package names to check
    
    @return list Subset of packages that need CPE generation (not in cache)
    
    @details
    **Filtering Logic:**
    1. For each package, call get_cached_cpes()
    2. If cache returns empty list, package needs generation
    3. If cache returns CPEs, skip generation
    4. Return list of packages requiring generation
    
    **Optimization:**
    This function avoids regenerating CPEs for packages we've already processed.
    On first run, all packages need generation. On subsequent runs, only new packages
    are processed, significantly reducing API calls to Google GenAI.
    
    **Return Value:**
    If cache is 100% effective, this returns only new packages.
    If cache is missing/corrupted, this returns all packages.
    
    **Logging:**
    Logs:
    - Each package that needs generation (DEBUG level)
    - Summary: "{count} packages need CPE generation out of {total}" (INFO)
    
    Example output:
    @code
    packages: ["curl", "openssl", "git", "nano"]
    cache: {"curl": [...], "nano": [...]}
    result: ["openssl", "git"]  # Only these need generation
    @endcode
    """
    packages_to_process = []
    
    for package in packages:
        cached_cpes = get_cached_cpes(package)
        if not cached_cpes:
            packages_to_process.append(package)
            logger.debug(f"Package {package} needs CPE generation")
        else:
            logger.debug(f"Using cached CPEs for {package}")
    
    logger.info(f"{len(packages_to_process)} packages need CPE generation out of {len(packages)}")
    return packages_to_process
