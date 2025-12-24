"""
@file output_formatter.py
@brief Terminal output formatting and color management module

Provides colored, formatted output for the vulnerability scanner with:
- ANSI color codes for terminal output
- Section and header formatting
- Status indicator functions (success, error, warning, info)
- Vulnerability detail display with clickable URLs
- Summary statistics formatting

@author Anton Moulin
@date 2025-12-24
@version 1.0

@details
Uses ANSI escape sequences for styling:
- Foreground colors for text
- Bold formatting for emphasis
- OSC 8 hyperlink protocol for clickable URLs in modern terminals
"""


class Colors:
    """
    @class Colors
    @brief ANSI color code constants for terminal styling
    
    Provides predefined color codes that can be combined with text
    for enhanced terminal output visibility and organization.
    """
    RESET = "\033[0m"
    BOLD = "\033[1m"
    
    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Background colors (optional)
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


def print_section(title):
    """
    Print a major section header with visual separators.
    
    @param title str Section title to display
    
    @details
    Creates a visually distinctive section break with:
    - Full-width separator lines
    - Centered title text
    - Cyan color for visibility
    
    Used for major workflow phases like "Processing Machine" or "Final Report"
    """
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{title.center(60)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}\n")


def print_machine_header(machine_name, host):
    """
    Print machine processing header.
    
    @param machine_name str Name of the machine
    @param host str IP address or hostname
    
    @details
    Displays machine identification for console output.
    Deprecated in favor of print_section() for consistency.
    """
    print(f"{Colors.BOLD}{Colors.BLUE}[MACHINE] {machine_name} ({host}){Colors.RESET}")


def print_success(message):
    """
    Print success message in green with checkmark symbol.
    
    @param message str Message to display
    
    @details
    Used to indicate successful operations such as:
    - API connectivity verified
    - Packages retrieved
    - Reports generated
    """
    print(f"{Colors.GREEN}✓ {message}{Colors.RESET}")


def print_info(message):
    """
    Print informational message in blue.
    
    @param message str Message to display
    
    @details
    Used for status updates and progress information.
    Indicates ongoing operations without success or failure status.
    """
    print(f"{Colors.BLUE}ℹ {message}{Colors.RESET}")


def print_warning(message):
    """
    Print warning message in yellow.
    
    @param message str Message to display
    
    @details
    Used to alert users to non-critical issues such as:
    - No new packages found
    - API rate limiting
    - Vulnerabilities discovered
    """
    print(f"{Colors.YELLOW}⚠ {message}{Colors.RESET}")


def print_error(message):
    """
    Print error message in red with X symbol.
    
    @param message str Message to display
    
    @details
    Used to indicate critical failures that may require attention.
    Examples: Connection failures, API errors, file I/O errors
    """
    print(f"{Colors.RED}✗ {message}{Colors.RESET}")


def print_vulnerability(cve_id, description, cve_url=None, score=None):
    """
    Print vulnerability information with clickable CVE.org URL.
    
    @param cve_id str CVE identifier (e.g., "CVE-2024-1234")
    @param description str Vulnerability description text
    @param cve_url str (optional) URL to CVE details page
    @param score float (optional) CVSS score if available
    
    @details
    Format example:
    @code
    [CVE-2024-1234] Vulnerability description text
    🔗 https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234
    @endcode
    
    URLs are formatted as OSC 8 hyperlinks for terminal click-through support
    in compatible terminals (iTerm2, GNOME Terminal, Windows Terminal, etc.)
    """
    if cve_url:
        # ANSI hyperlink format for terminal clickable links (OSC 8)
        clickable_url = f"\033]8;;{cve_url}\033\\{cve_url}\033]8;;\033\\"
        if score:
            print(f"  {Colors.RED}[{cve_id}]{Colors.RESET} {description}")
            print(f"    {Colors.BLUE}🔗 {clickable_url}{Colors.RESET} (Score: {score})")
        else:
            print(f"  {Colors.RED}[{cve_id}]{Colors.RESET} {description}")
            print(f"    {Colors.BLUE}🔗 {clickable_url}{Colors.RESET}")
    else:
        if score:
            print(f"  {Colors.RED}[{cve_id}]{Colors.RESET} {description} (Score: {score})")
        else:
            print(f"  {Colors.RED}[{cve_id}]{Colors.RESET} {description}")


def print_package_list(packages, title="Packages"):
    """
    Print a formatted list of packages.
    
    @param packages list Package names to display
    @param title str (optional) Header title for the list
    
    @details
    Displays packages as a bulleted list with formatting.
    Useful for debugging and status reporting.
    """
    if packages:
        print(f"{Colors.BOLD}{title}:{Colors.RESET}")
        for pkg in packages:
            print(f"  • {pkg}")
    else:
        print(f"{Colors.BOLD}{title}:{Colors.RESET} {Colors.YELLOW}None{Colors.RESET}")


def print_stats(total_machines, machines_processed, total_vulnerabilities):
    """
    Print final processing statistics and summary.
    
    @param total_machines int Total machines in inventory
    @param machines_processed int Successfully processed machines
    @param total_vulnerabilities int Total CVEs found across all machines
    
    @details
    Displays a formatted summary table with:
    - Total machines scanned
    - Machines successfully processed
    - Total vulnerabilities discovered
    
    Creates clear visual separation with borders and colors.
    """
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Processing Summary:{Colors.RESET}")
    print(f"  • Total machines: {Colors.BLUE}{total_machines}{Colors.RESET}")
    print(f"  • Machines processed: {Colors.GREEN}{machines_processed}{Colors.RESET}")
    print(f"  • Total vulnerabilities found: {Colors.RED}{total_vulnerabilities}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}\n")
    """ANSI color codes"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    
    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Background colors (optional)
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


def print_section(title):
    """Print a major section header"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{title.center(60)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}\n")


def print_machine_header(machine_name, host):
    """Print machine processing header"""
    print(f"{Colors.BOLD}{Colors.BLUE}[MACHINE] {machine_name} ({host}){Colors.RESET}")


def print_success(message):
    """Print success message in green"""
    print(f"{Colors.GREEN}✓ {message}{Colors.RESET}")


def print_info(message):
    """Print info message in blue"""
    print(f"{Colors.BLUE}ℹ {message}{Colors.RESET}")


def print_warning(message):
    """Print warning message in yellow"""
    print(f"{Colors.YELLOW}⚠ {message}{Colors.RESET}")


def print_error(message):
    """Print error message in red"""
    print(f"{Colors.RED}✗ {message}{Colors.RESET}")


def print_vulnerability(cve_id, description, cve_url=None, score=None):
    """Print vulnerability information with clickable URL"""
    if cve_url:
        # ANSI hyperlink format for terminal clickable links (OSC 8)
        clickable_url = f"\033]8;;{cve_url}\033\\{cve_url}\033]8;;\033\\"
        if score:
            print(f"  {Colors.RED}[{cve_id}]{Colors.RESET} {description}")
            print(f"    {Colors.BLUE}🔗 {clickable_url}{Colors.RESET} (Score: {score})")
        else:
            print(f"  {Colors.RED}[{cve_id}]{Colors.RESET} {description}")
            print(f"    {Colors.BLUE}🔗 {clickable_url}{Colors.RESET}")
    else:
        if score:
            print(f"  {Colors.RED}[{cve_id}]{Colors.RESET} {description} (Score: {score})")
        else:
            print(f"  {Colors.RED}[{cve_id}]{Colors.RESET} {description}")


def print_package_list(packages, title="Packages"):
    """Print a list of packages nicely"""
    if packages:
        print(f"{Colors.BOLD}{title}:{Colors.RESET}")
        for pkg in packages:
            print(f"  • {pkg}")
    else:
        print(f"{Colors.BOLD}{title}:{Colors.RESET} {Colors.YELLOW}None{Colors.RESET}")


def print_stats(total_machines, machines_processed, total_vulnerabilities):
    """Print processing statistics"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Processing Summary:{Colors.RESET}")
    print(f"  • Total machines: {Colors.BLUE}{total_machines}{Colors.RESET}")
    print(f"  • Machines processed: {Colors.GREEN}{machines_processed}{Colors.RESET}")
    print(f"  • Total vulnerabilities found: {Colors.RED}{total_vulnerabilities}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}\n")
