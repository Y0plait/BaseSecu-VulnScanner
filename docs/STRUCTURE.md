## Project Structure

The codebase has been reorganized into functional modules grouped by their purpose:

```
.
├── main.py                          # Root entry point (dispatches to src/core/main.py)
├── requirements.txt                 # Python dependencies
├── inventory.ini                    # Machine inventory configuration
├── cache/                           # Runtime cache directory
│   ├── vulnerability_cache.db       # SQLite vulnerability cache
│   ├── cpe_cache.json               # CPE lookup cache
│   └── machines/                    # Per-machine caches
│       ├── srv01/
│       │   ├── installed_packages.json
│       │   └── vulnerability_report.json
│       ├── srv02/
│       └── srv03/
├── cpe/                             # CPE list files (generated)
├── logs/                            # Application logs
├── src/                             # Source code (organized by function)
│   ├── __init__.py
│   ├── core/                        # Main orchestration
│   │   └── main.py                  # CLI entry point and orchestration logic
│   ├── acquisition/                 # Data collection from machines
│   │   ├── __init__.py
│   │   ├── pkg_finder.py            # SSH-based package discovery
│   │   └── machine_processor.py     # Machine-level processing
│   ├── caching/                     # Database and configuration
│   │   ├── __init__.py
│   │   ├── cache_db.py              # SQLite vulnerability cache management
│   │   └── constants.py             # Global configuration and API keys
│   ├── matching/                    # CPE generation and NVD matching
│   │   ├── __init__.py
│   │   └── cpe_matcher.py           # AI-based CPE generation using Google GenAI
│   └── reporting/                   # Report generation and output
│       ├── __init__.py
│       ├── vulnerability_checker.py # NVD API queries and CVE matching
│       ├── report_generator.py      # JSON report generation
│       └── output_formatter.py      # Terminal output formatting
└── .env/                            # Python virtual environment
```

### Module Organization

#### **src/core** - Main Orchestration
- **main.py**: Command-line interface, configuration parsing, and workflow orchestration
  - Processes inventory files
  - Manages CLI arguments (--inventory, --flush-cache, --force-check)
  - Coordinates data flow between other modules

#### **src/acquisition** - Data Collection
- **pkg_finder.py**: SSH-based remote package discovery
  - Connects to machines via SSH
  - Discovers installed packages and versions
  - Manages package caching
  
- **machine_processor.py**: Machine-level orchestration
  - Processes machines from inventory
  - Generates CPEs for discovered packages
  - Coordinates acquisition and matching workflows

#### **src/caching** - Persistence Layer
- **cache_db.py**: SQLite vulnerability cache
  - Stores CVE/CWE data from NVD API
  - Implements caching to reduce API calls
  - Manages database lifecycle
  
- **constants.py**: Global configuration
  - API keys (Google GenAI, NVD NIST)
  - Cache directory configuration
  - Rate limiting parameters
  - Default values

#### **src/matching** - CPE Generation & Matching
- **cpe_matcher.py**: AI-based CPE generation
  - Uses Google GenAI API to generate CPEs from package information
  - Validates CPE format against NVD standards
  - Manages CPE caching
  - Temperature=0 for deterministic output

#### **src/reporting** - Output Generation
- **vulnerability_checker.py**: NVD API integration
  - Queries NVD NIST API for vulnerabilities
  - Matches CPEs against NVD database
  - Retrieves CVE descriptions and details
  
- **report_generator.py**: JSON report generation
  - Creates structured JSON vulnerability reports
  - Generates CVE.org links for detailed information
  - Organizes vulnerabilities by CPE
  
- **output_formatter.py**: Terminal output
  - Formats vulnerabilities for console display
  - Provides colored, readable output
  - Supports progress indicators and statistics

### Data Flow

```
inventory.ini
    ↓
[src/core/main.py] - Orchestration
    ↓
[src/acquisition/machine_processor.py]
    ├→ [src/acquisition/pkg_finder.py] - SSH discovery
    └→ [src/matching/cpe_matcher.py] - AI CPE generation
        ↓
    [src/caching/cache_db.py] - Cache storage
    [src/caching/constants.py] - Configuration
    ↓
[src/reporting/vulnerability_checker.py] - NVD API queries
    ├→ [src/reporting/report_generator.py] - JSON reports
    └→ [src/reporting/output_formatter.py] - Console output
    ↓
cache/machines/{machine}/vulnerability_report.json
```

### Benefits of This Structure

1. **Clear Separation of Concerns**: Each module has a specific responsibility
2. **Easy Navigation**: Related functionality is grouped together
3. **Simplified Testing**: Modules can be tested independently
4. **Better Maintainability**: Changes to one layer don't affect others
5. **Scalability**: New features can be added to appropriate modules
6. **Import Clarity**: Full paths show exactly where dependencies come from

### Running the Application

```bash
# From the project root
python3 main.py [OPTIONS]

# Available options
python3 main.py --help
python3 main.py --inventory custom_inventory.ini
python3 main.py --flush-cache
python3 main.py --force-check
```

The root `main.py` acts as a simple dispatcher that imports and runs `src/core/main.py`, maintaining backward compatibility with existing scripts while organizing the implementation code.
