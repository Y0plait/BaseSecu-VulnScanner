# Network Visualization Integration - Implementation Summary

## Overview

Integrated network topology visualization into the HTML vulnerability report using the `visualnet-scanner.sh` script. SVG network diagrams are now generated for each scanned host and embedded directly into the HTML report.

## Changes Made

### 1. New Module: `src/reporting/network_visualizer.py`
Created a new module to handle network visualization generation:

**Key Functions:**
- `generate_network_svg_for_host(host_address, machine_name)`: Executes visualnet-scanner.sh for a specific host and generates SVG
- `svg_to_base64(svg_file_path)`: Converts SVG to base64 for embedding
- `read_svg_content(svg_file_path)`: Reads SVG file as text for inline embedding
- `generate_network_visualizations(machines_config)`: Batch generation for all machines

**Features:**
- Automatic execution of visualnet-scanner.sh script
- Error handling with fallbacks
- Timeout protection (5 minutes per scan)
- File validation (checks existence, size, permissions)
- Logging of all operations

### 2. Updated HTML Template: `templates/vulnerability_report.html`

Added Network Topology section to each machine report:
```html
<!-- Network Topology Visualization -->
{% if network_visualizations.get(machine_name, {}).get('svg_content') %}
    <div class="border-t border-gray-200 p-6 bg-gray-50">
        <h4 class="text-lg font-semibold text-gray-900 mb-4 flex items-center">
            <span class="material-icons mr-2">share</span>
            Network Topology
        </h4>
        <div class="bg-white border border-gray-200 rounded-lg p-4 overflow-x-auto">
            {{ network_visualizations[machine_name].svg_content|safe }}
        </div>
    </div>
{% endif %}
```

**Features:**
- SVG is embedded directly in HTML (no external file dependencies)
- Uses `|safe` filter to render SVG markup
- Conditional rendering (only shows if SVG was generated)
- Responsive design with horizontal scroll for large diagrams
- Material Design icon for visual consistency

### 3. Updated `src/reporting/html_report_generator.py`

**Modified Function:** `generate_html_report(output_file=None, machines_config=None)`

**Changes:**
- Added optional `machines_config` parameter
- Integrated network visualization generation
- Network visualizations passed to template context
- Error handling for visualization failures

**Implementation:**
```python
# Generate network visualizations if machines_config provided
network_visualizations = {}
if machines_config:
    try:
        from src.reporting import network_visualizer as nv
        logger.info("Generating network visualizations...")
        network_visualizations = nv.generate_network_visualizations(machines_config)
    except Exception as e:
        logger.warning(f"Failed to generate network visualizations: {e}")
```

### 4. Updated `src/core/main.py`

**Two Updates:**

#### A. Report-Only Mode (lines 188-220)
- Now loads inventory and passes machines_config to report generator
- Allows network SVGs to be regenerated even in report-only mode

#### B. Normal Scan Mode (lines 355-375)
- Converts ConfigParser to dict format
- Passes machines_config to `generate_html_report()`
- Includes network visualizations in final report

## Workflow

```
Vulnerability Scanning Process
│
├─ Scan machines for packages & vulnerabilities
├─ Generate vulnerability reports (JSON)
│
└─ HTML Report Generation
   ├─ Aggregate vulnerability data from JSON files
   ├─ FOR EACH MACHINE:
   │  ├─ Execute: visualnet-scanner.sh <host_ip>
   │  ├─ Generate: SVG network topology
   │  ├─ Read: SVG file content
   │  └─ Embed: SVG in machine section
   ├─ Render: Jinja2 HTML template with:
   │  ├─ Statistics
   │  ├─ Machine reports
   │  ├─ Network visualizations
   │  └─ Vulnerability tables
   └─ Output: HTML report with integrated SVGs
```

## File Structure

```
cache/machines/
├── srv01/
│   ├── vulnerability_report.json
│   ├── network_topology.svg          ← NEW
│   ├── cpe_list_srv01.txt
│   └── installed_packages.json
├── srv02/
│   ├── vulnerability_report.json
│   ├── network_topology.svg          ← NEW
│   ├── cpe_list_srv02.txt
│   └── installed_packages.json
└── srv03/
    ├── vulnerability_report.json
    ├── network_topology.svg          ← NEW
    ├── cpe_list_srv03.txt
    └── installed_packages.json

cache/vulnerability_report.html       ← Contains embedded SVGs
```

## Usage

### Generate Full Report with Network Visualization
```bash
python main.py --inventory inventory.ini
```
This will:
1. Scan all machines
2. Collect packages and vulnerabilities
3. Generate network SVGs for each host
4. Create HTML report with embedded network diagrams

### Generate Report from Cache (with Network SVGs)
```bash
python main.py --report-only
```
This will:
1. Load existing vulnerability data
2. Generate fresh network SVGs (if nmap/visualnet-scanner available)
3. Create HTML report with network diagrams

## Error Handling

The network visualization module gracefully handles errors:

1. **Missing visualnet-scanner.sh**: Warning logged, SVG skipped
2. **Script not executable**: Warning logged, SVG skipped
3. **Scan timeout** (>5 min): Error logged, SVG skipped
4. **SVG generation failure**: Error logged, SVG skipped
5. **Empty SVG file**: Error logged, SVG skipped
6. **Network issues**: Exception caught, visualization skipped

**Result:** If network visualization fails, the report still generates successfully with all vulnerability data intact.

## Requirements

The feature requires the visualnet-scanner.sh script to be present in the project root:
- `./visualnet-scanner.sh` - Must be executable
- Dependencies: `nmap`, `graphviz` (dot command)
- Optional: `nmap-formatter` binary

If any dependency is missing, network visualization is automatically skipped.

## Technical Details

### SVG Embedding
- SVGs are read as text and embedded directly in HTML
- Uses Jinja2's `|safe` filter to preserve SVG markup
- No data URI encoding needed (keeps HTML readable)
- Allows interactive SVG (hovering, scrolling within diagram)

### Network Scanning
- Each machine is scanned individually
- Scan target: machine's IP address or network
- Output format: SVG (vector graphics)
- Timeout: 5 minutes per scan
- Caching: SVGs stored in machine's cache directory

### Template Variables
```python
network_visualizations = {
    'srv01': {
        'svg_path': 'cache/machines/srv01/network_topology.svg',
        'svg_content': '<svg>...</svg>',  # Actual SVG markup
        'generated': True
    },
    'srv02': {
        'svg_path': None,
        'svg_content': None,
        'generated': False  # Generation failed
    }
}
```

## HTML Report Structure

Each machine section now includes:

```html
<div class="machine-report">
    <div class="header">Machine name, timestamp, vuln count</div>
    
    <!-- NEW: Network Topology Section -->
    <div class="network-section">
        <h4>Network Topology</h4>
        <div class="svg-container">
            <!-- Embedded SVG diagram -->
        </div>
    </div>
    
    <div class="stats">Severity distribution</div>
    <div class="vulnerabilities-table">CVE details</div>
</div>
```

## Benefits

1. **Visual Context**: Network topology shows connections and exposed services
2. **Integrated Report**: No need for separate network diagrams
3. **Self-Contained**: HTML file includes all SVGs (single file delivery)
4. **Professional Look**: Clean, modern design with Material Icons
5. **Responsive**: SVGs scale and scroll appropriately
6. **Graceful Degradation**: Works even if network scanning fails

## Testing

To test the feature:

```bash
# Full scan with network visualization
python main.py --inventory inventory.ini

# Regenerate report from cache with new SVGs
python main.py --report-only

# Check generated report
open cache/vulnerability_report.html
```

Look for:
- Network Topology sections in each machine report
- SVG diagrams showing hosts and connections
- Proper styling and layout of diagrams
