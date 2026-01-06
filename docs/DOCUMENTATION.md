# Technical Documentation

> Complete API reference and implementation details for developers

## Overview

This document provides comprehensive technical documentation for the vulnerability scanner codebase. All Python modules include Doxygen-format docstrings with:
- Clear module purposes and responsibilities
- Detailed function signatures with `@param`, `@return`, `@throws` tags
- Implementation algorithms and design decisions
- Error handling strategies
- Cache structures and data formats
- Integration points between modules

## Table of Contents

1. [Core Modules](#core-modules)
2. [Data Structures](#data-structures)
3. [Design Patterns](#design-patterns)
4. [API Reference](#api-reference)
5. [Cache Structures](#cache-structures)
6. [Error Handling](#error-handling)

---

## Core Modules

### **src/core/main.py** (391 lines)

**Purpose:** System orchestrator coordinating the entire vulnerability scanning workflow

**CLI Interface:**
```python
python main.py [OPTIONS]
  --inventory FILE          # Configuration file (default: inventory.ini)
  --flush-cache            # Remove all caches before scanning
  --force-check            # Check all packages (ignore delta detection)
  --report-only            # Generate HTML from cache without scanning
  --help                   # Show help message
```

**Main Workflow:**
1. Parse arguments and load inventory
2. Initialize Google GenAI API
3. Test NVD API connectivity
4. For each machine:
   - Retrieve installed packages
   - Generate CPEs for packages
   - Retrieve hardware information
   - Generate CPEs for hardware
   - Query NVD for vulnerabilities
   - Generate JSON report
5. Aggregate and generate HTML report

**Key Functions:**
- `main()` - Entry point with full orchestration
- `parse_arguments()` - CLI argument parsing
- `flush_all_caches()` - Remove cache directories and database

---

### **src/acquisition/machine_processor.py** (250+ lines)

**Purpose:** Machine-level data acquisition and CPE generation orchestration

**Responsibilities:**
- SSH connection and package discovery
- Hardware information retrieval
- CPE generation delegation to `cpe_matcher`
- Delta detection and caching

**Key Functions:**

#### `process_machine_packages(config, machine) -> tuple`
- **Input:** ConfigParser with machine section, machine name
- **Output:** (all_packages: list, new_packages: list)
- **Process:**
  1. Check package cache for previous run
  2. Call `pkg_finder.get_installed_packages_linux()`
  3. Detect new/removed packages (delta)
  4. Save updated cache
  5. Log statistics

#### `generate_cpes_for_packages(packages, machine, cpe_matcher) -> dict`
- **Input:** Package list, machine name, CPE matcher instance
- **Output:** `{package_name: [cpe_string, ...]}`
- **Process:**
  1. Check CPE cache for existing entries
  2. Filter packages needing generation
  3. Call `cpe_matcher.ask_for_cpe()` with batch
  4. Save and return results

#### `process_machine_hardware(config, machine) -> dict`
- **Input:** ConfigParser, machine name
- **Output:** Hardware info dict (vendor, model, family, etc.)
- **Process:**
  1. Verify machine type is Linux
  2. Call `pkg_finder.get_hardware_info()`
  3. Parse lscpu output
  4. Log and display results

---

### **src/acquisition/pkg_finder.py** (180+ lines)

**Purpose:** SSH-based package and hardware discovery

**Key Functions:**

#### `get_installed_packages_linux(config, machine) -> list`
- **SSH Commands by Distribution:**
  ```bash
  apt list --installed          # Debian/Ubuntu
  rpm -qa                       # RedHat/Fedora/CentOS
  apk list --installed          # Alpine
  pacman -Q                      # Arch
  ```
- **Output Format:** `[("package-name", "version.number")]`
- **Sanitization:** Removes arch, distribution tags, metadata

#### `get_hardware_info(config, machine) -> dict`
- **SSH Command:** `lscpu` (standard on all Linux distributions)
- **Output Structure:**
  ```python
  {
      'vendor_id': 'GenuineIntel',
      'model_name': 'Intel(R) Xeon(R) Platinum 8280',
      'family': '6',
      'model': '85',
      'stepping': '11',
      'flags': 'fpu vme de pse tsc msr pae mce ...',
      'cores': '56',
      'threads': '2'
  }
  ```

#### `get_new_packages(all_packages, machine) -> list`
- Delta detection between previous and current runs
- Returns only newly installed/updated packages
- Reduces CPE generation API calls significantly

---

### **src/matching/cpe_matcher.py** (350+ lines)

**Purpose:** AI-powered CPE generation from package/hardware descriptions

**Model Configuration:**
- **Model:** Google Gemini Flash 2.5
- **Temperature:** 0 (deterministic output)
- **Thinking Budget:** 0 (disabled for speed)
- **Max Tokens:** 8000

**Key Functions:**

#### `ask_for_cpe(packages, machine, is_hardware=False) -> dict`
- **Input:** Package list or hardware description, machine name, type flag
- **Output:** `{package: [cpe_string, ...]}`
- **Prompting Strategy:**
  - Batch processing (500+ items in single call when possible)
  - Specialized prompts for software vs hardware
  - Context preservation across calls

**CPE Format (CPE 2.3):**
```
cpe:2.3:PART:VENDOR:PRODUCT:VERSION:UPDATE:EDITION:LANGUAGE:SW_EDITION:TARGET_SW:TARGET_HW:OTHER

PART: a=application, h=hardware, o=operating system
```

---

### **src/caching/cache_db.py** (200+ lines)

**Purpose:** SQLite vulnerability database caching

**Database File:** `cache/vulnerability_cache.db`

**Schema:**
```sql
CREATE TABLE cpe_index (
    id INTEGER PRIMARY KEY,
    cpe_string TEXT UNIQUE NOT NULL,
    last_fetched TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY,
    cpe_string TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    description TEXT,
    cached_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(cpe_string, cve_id),
    FOREIGN KEY(cpe_string) REFERENCES cpe_index(cpe_string)
);
```

**Key Functions:**

#### `get_db() -> sqlite3.Connection`
- Singleton pattern with lazy initialization
- Auto-creates tables if missing

#### `get_vulnerabilities(cpe_string, api_key) -> list`
- **Lookup Strategy:** Cache-first, API fallback
- 80-90% reduction in API calls
- Local queries (5ms) vs network calls (500ms+)

---

### **src/reporting/vulnerability_checker.py** (200+ lines)

**Purpose:** NVD API querying with rate limiting and error handling

**API Configuration:**
- **Rate Limit:** 50 requests/30 seconds (with API key)
- **Delay:** 0.6 seconds between requests
- **Timeout:** 30 seconds per request

**Error Handling:**

| HTTP Status | Meaning | Action |
|-------------|---------|--------|
| 200 | Success | Cache results |
| 404 | Invalid CPE | Mark as invalid, skip future |
| 429 | Rate limit exceeded | Exponential backoff, retry |
| 503 | Service unavailable | Exponential backoff, retry |

---

### **src/reporting/report_generator.py** (150+ lines)

**Purpose:** JSON vulnerability report generation

**Report Structure:**
```json
{
  "machine": "srv01",
  "timestamp": "2025-01-06T18:30:00Z",
  "vulnerabilities": {
    "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*": [
      {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2...",
        "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
      }
    ]
  }
}
```

---

### **src/reporting/output_formatter.py** (250+ lines)

**Purpose:** Colored terminal output with formatted sections

**ANSI Color Codes:**
```python
class Colors:
    RED = '\033[91m'      # Errors
    GREEN = '\033[92m'    # Success
    YELLOW = '\033[93m'   # Warnings
    BLUE = '\033[94m'     # Info
    CYAN = '\033[96m'     # Headers
    BOLD = '\033[1m'      # Emphasis
```

---

## Cache Structures

### Package Cache
**File:** `cache/machines/{machine}/installed_packages.json`

```json
{
  "timestamp": "2025-01-06T18:00:00Z",
  "packages": [
    ["openssh-server", "1:7.4p1-21"],
    ["openssl", "1.1.1k-1+deb9u1"]
  ]
}
```

### CPE Cache
**File:** `cache/cpe_cache.json`

```json
{
  "openssh-server": [
    {
      "cpe": "cpe:2.3:a:openssh:openssh:7.4p1:*:*:*:*:*:*:*",
      "valid": true
    }
  ]
}
```

---

## Design Patterns

### 1. Two-Level Caching
- **Level 1:** Package delta detection (avoids regenerating CPEs)
- **Level 2:** CPE-to-CVE mapping (avoids redundant API calls)

### 2. Rate Limiting with Exponential Backoff
```python
attempt = 0
while attempt < MAX_RETRIES:
    try:
        response = nvdlib.searchCPE(cpe, key=api_key)
        return response
    except HTTPError(429):  # Rate limited
        wait_time = 2 ** attempt
        time.sleep(wait_time)
        attempt += 1
```

### 3. Graceful Degradation
Each layer handles its own errors:
- SSH Layer: Connection failures → skip machine, log error
- AI Layer: API errors → use default CPE, log warning
- NVD API Layer: Rate limiting → retry with backoff
- Report Generation: Missing data → skip sections, generate partial report

---

## Integration Points

```
main.py
  ├─ machine_processor.py
  │   ├─ pkg_finder.py (SSH)
  │   └─ cpe_matcher.py (GenAI)
  ├─ vulnerability_checker.py (NVD API)
  │   └─ cache_db.py (SQLite)
  ├─ report_generator.py (JSON)
  ├─ output_formatter.py (Terminal)
  └─ html_report_generator.py (HTML)
      ├─ network_visualizer.py (SVG)
      └─ templates/vulnerability_report.html (Jinja2)
```

---

## Performance Considerations

### API Optimization
- Cache-first strategy reduces NVD API calls by 80-90%
- Batch CPE generation (500+ items per call)
- Rate limiting prevents IP bans and errors

### Memory Usage
- Streams JSON report generation (not loaded entirely)
- SQLite for large vulnerability datasets (not in-memory)
- Generator patterns for large package lists

### Network Impact
- Delta detection reduces SSH calls
- Minimal Nmap scanning for network visualization
- Base64 embedding avoids external file dependencies

---

## Debugging Tips

### Enable Debug Logging
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Trace API Calls
```bash
tail -f logs/vulnerability_scan_*.log | grep "API\|NVD"
```

### Inspect Cache Files
```bash
# View package cache
cat cache/machines/srv01/installed_packages.json | python -m json.tool

# View CPE cache
cat cache/cpe_cache.json | python -m json.tool

# Query SQLite directly
sqlite3 cache/vulnerability_cache.db "SELECT COUNT(*) FROM vulnerabilities;"
```

---

## References

- [CPE Specification](https://nvd.nist.gov/products/cpe)
- [NVD API Documentation](https://nvd.nist.gov/developers)
- [Google Generative AI](https://ai.google.dev)
- [Paramiko SSH Library](https://www.paramiko.org)
- [Jinja2 Templates](https://jinja.palletsprojects.com)
