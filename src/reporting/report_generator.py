"""
@file report_generator.py
@brief Vulnerability report generation and CVE URL management module

Generates structured JSON vulnerability reports for each scanned machine with
comprehensive CVE data including identifiers, descriptions, URLs, and publication dates.

Reports are designed for:
- Automated integration with vulnerability management systems
- Direct consumption by web dashboards and APIs
- Export to SIEM platforms
- Custom analysis tools

@author Anton Moulin
@date 2025-12-24
@version 1.0

@details
**Features:**

- Per-Machine JSON Reports:
  * Machine identification and scan timestamp
  * CPE to vulnerability mappings
  * CVE identifiers with descriptions
  * Direct URLs to CVE.org for detailed information
  * Publication dates for CVE tracking
  
- Report Structure:
  * Organized by affected components (CPEs)
  * Groups vulnerabilities per component
  * Includes complete CVE metadata
  
- CVE URL Generation:
  * Generates official CVE.org links
  * Format: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-XXXX-XXXXX
  * Clickable in modern terminals
  
- Persistence:
  * Saves to: cache/machines/{machine}/vulnerability_report.json
  * Uses JSON format for interoperability
  * Includes ISO 8601 timestamps
  
- Integration:
  * Reports are read by html_report_generator.py for dashboards
  * Used for severity estimation and statistics
  * Consumed by external tools via JSON import

**Report Format:**

```json
{
  "machine": "srv01",
  "timestamp": "2026-01-06T12:00:00.000000",
  "cpes_with_vulnerabilities": [
    {
      "cpe": "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*",
      "vulnerabilities": [
        {
          "cve_id": "CVE-2024-1234",
          "description": "Vulnerability description from NVD",
          "cve_url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234",
          "published_date": "2024-05-15T00:00:00Z"
        }
      ]
    }
  ]
}
```
"""

import json
import os
from datetime import datetime
import logging
from src.caching.constants import CACHE_DIR

logger = logging.getLogger(__name__)


def generate_cve_url(cve_id):
    """
    Generate a direct link to CVE details on cve.mitre.org.
    
    @param cve_id str CVE identifier (e.g., "CVE-2024-1234")
    
    @return str Full URL to CVE details page
    
    @details
    Format: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-XXXX-XXXXX
    
    These URLs are included in:
    - Terminal output (clickable in modern terminals)
    - JSON reports for reference
    """
    return f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"


def save_machine_report(machine_name, vulnerabilities_data):
    """
    Generate and save JSON vulnerability report for a machine.
    
    Creates a timestamped JSON file containing all vulnerabilities found
    on a machine, organized by CPE (Common Platform Enumeration) with
    clickable CVE references and publication dates.
    
    @param machine_name str Name of the machine being reported
                           Format: hostname or identifier (e.g., "srv01")
    @param vulnerabilities_data dict Vulnerability data structure
                                    Format: {cpe: [{cve_id, description, published_date}, ...], ...}
    
    @return str Path to generated report file, or None on failure
            Example: "cache/machines/srv01/vulnerability_report.json"
    
    @details
    **Output File Location:**
    
    - Directory: cache/machines/{machine_name}/
    - Filename: vulnerability_report.json
    - Permissions: User readable
    - Format: JSON with 2-space indentation
    
    **Report Structure:**
    
    ```json
    {
        "machine": "srv01",
        "timestamp": "2025-12-24T14:30:45.123456",
        "cpes_with_vulnerabilities": [
            {
                "cpe": "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*",
                "vulnerabilities": [
                    {
                        "cve_id": "CVE-2024-1234",
                        "description": "Vulnerability description from NVD",
                        "cve_url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234",
                        "published_date": "2024-05-15T00:00:00Z"
                    }
                ]
            }
        ]
    }
    ```
    
    **Data Processing:**
    
    1. Creates machine directory if it doesn't exist
    2. Iterates through vulnerabilities_data dictionary
    3. For each CPE with vulnerabilities:
       - Creates CPE entry with empty vulnerabilities list
       - For each vulnerability:
         - Extracts cve_id, description, published_date
         - Generates CVE URL using generate_cve_url()
         - Appends to vulnerabilities list
       - Appends CPE entry to report
    4. Writes report as formatted JSON
    5. Logs success or failure
    
    **Error Handling:**
    
    - Missing machine name: Returns None
    - Empty vulnerabilities_data: Creates empty report
    - File write failure: Logs error, returns None
    - Invalid UTF-8: Logs and skips problematic entries
    
    **Timestamp Format:**
    
    - ISO 8601 format with microseconds
    - Timezone: Local system timezone
    - Example: "2025-12-24T14:30:45.123456"
    
    @note
    - Report is human-readable (not minified)
    - Directory is created automatically if missing
    - Overwrites existing report without warning
    - Logs generation details to logger for audit trail
    """
    report_dir = os.path.join(CACHE_DIR, "machines", machine_name)
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
    
    # Build report structure
    report = {
        "machine": machine_name,
        "timestamp": datetime.now().isoformat(),
        "cpes_with_vulnerabilities": []
    }
    
    # Process vulnerabilities by CPE
    for cpe, vulns in vulnerabilities_data.items():
        if vulns:  # Only include CPEs with vulnerabilities
            cpe_entry = {
                "cpe": cpe,
                "vulnerabilities": []
            }
            
            for vuln in vulns:
                cve_entry = {
                    "cve_id": vuln["cve_id"],
                    "description": vuln["description"],
                    "cve_url": generate_cve_url(vuln["cve_id"])
                }
                if "published_date" in vuln:
                    cve_entry["published_date"] = vuln["published_date"]
                cpe_entry["vulnerabilities"].append(cve_entry)
            
            report["cpes_with_vulnerabilities"].append(cpe_entry)
    
    # Save report to JSON file
    report_file = f"{report_dir}/vulnerability_report.json"
    try:
        with open(report_file, "w") as f:
            f.write(json.dumps(report, indent=2))
        logger.info(f"Vulnerability report saved for {machine_name}: {report_file}")
        return report_file
    except Exception as e:
        logger.error(f"Error saving vulnerability report for {machine_name}: {e}")
        return None


def get_total_vulnerabilities_from_report(report_dict):
    """
    Count total vulnerabilities in a report structure.
    
    @param report_dict dict Report dictionary (as generated by save_machine_report)
    
    @return int Total number of vulnerabilities across all CPEs
    
    @details
    Useful for statistics and summary generation.
    """
    total = 0
    for cpe_entry in report_dict.get("cpes_with_vulnerabilities", []):
        total += len(cpe_entry.get("vulnerabilities", []))
    return total
