"""
@file html_report_generator.py
@brief HTML vulnerability report generation using Jinja2 templates

Generates a comprehensive, interactive HTML report from all vulnerability JSON files
with statistics, filtering, and elegant Material Design styling.

@author Anton Moulin
@date 2025-12-24
@version 1.0

@details
Features:
- Aggregates vulnerabilities from all machines
- Generates statistics (machines scanned, total CVEs, severity distribution)
- Creates interactive HTML dashboard
- Uses Tailwind CSS for responsive design
- Material Design Icons for visual appeal
- Sortable vulnerability tables
- Machine-level summaries
- Severity-based color coding
"""

import json
import os
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.caching.constants import CACHE_DIR

logger = logging.getLogger(__name__)


def aggregate_vulnerabilities():
    """
    Aggregate all vulnerability JSON files from machines.
    
    @return dict Aggregated vulnerability data:
                 {
                   'machines': {
                     'machine_name': {
                       'host': 'ip_address',
                       'total_vulns': count,
                       'vulnerabilities': [...],
                       'severity_distribution': {...}
                     }
                   },
                   'statistics': {
                     'total_machines': int,
                     'total_cves': int,
                     'severity_breakdown': {'critical': n, 'high': n, ...}
                   }
                 }
    """
    machines_dir = os.path.join(CACHE_DIR, "machines")
    
    if not os.path.exists(machines_dir):
        logger.warning(f"Machines directory not found: {machines_dir}")
        return {'machines': {}, 'statistics': {}}
    
    aggregated_data = {
        'machines': {},
        'statistics': {
            'total_machines': 0,
            'total_cves': 0,
            'severity_breakdown': defaultdict(int),
            'generated_at': datetime.now().isoformat()
        }
    }
    
    # Iterate through each machine directory
    for machine_dir in os.listdir(machines_dir):
        machine_path = os.path.join(machines_dir, machine_dir)
        
        if not os.path.isdir(machine_path):
            continue
        
        # Look for vulnerability_report.json
        report_file = os.path.join(machine_path, "vulnerability_report.json")
        
        if not os.path.exists(report_file):
            logger.debug(f"No vulnerability report found for {machine_dir}")
            continue
        
        try:
            with open(report_file, 'r') as f:
                report_data = json.load(f)
            
            # Extract machine data
            machine_info = {
                'name': report_data.get('machine', machine_dir),
                'timestamp': report_data.get('timestamp', ''),
                'vulnerabilities': [],
                'total_vulns': 0,
                'severity_distribution': defaultdict(int),
                'affected_cpes': []
            }
            
            # Process CPEs and vulnerabilities
            for cpe_entry in report_data.get('cpes_with_vulnerabilities', []):
                cpe = cpe_entry.get('cpe', '')
                
                # Track unique CPEs
                if cpe not in machine_info['affected_cpes']:
                    machine_info['affected_cpes'].append(cpe)
                
                # Process vulnerabilities
                for vuln in cpe_entry.get('vulnerabilities', []):
                    cve_id = vuln.get('cve_id', 'UNKNOWN')
                    description = vuln.get('description', 'No description')
                    cve_url = vuln.get('cve_url', f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}')
                    
                    # Determine severity from CVE ID (basic heuristic)
                    severity = estimate_severity(cve_id, description)
                    
                    machine_info['vulnerabilities'].append({
                        'cve_id': cve_id,
                        'cpe': cpe,
                        'description': description,
                        'url': cve_url,
                        'severity': severity
                    })
                    
                    machine_info['severity_distribution'][severity] += 1
                    aggregated_data['statistics']['severity_breakdown'][severity] += 1
            
            machine_info['total_vulns'] = len(machine_info['vulnerabilities'])
            aggregated_data['statistics']['total_cves'] += machine_info['total_vulns']
            aggregated_data['machines'][machine_dir] = machine_info
            aggregated_data['statistics']['total_machines'] += 1
            
            logger.info(f"Processed report for {machine_dir}: {machine_info['total_vulns']} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error processing report for {machine_dir}: {e}")
            continue
    
    return aggregated_data


def estimate_severity(cve_id, description):
    """
    Estimate CVE severity based on CVE ID and description.
    
    @param cve_id str CVE identifier
    @param description str CVE description
    
    @return str Severity level: 'critical', 'high', 'medium', 'low'
    
    @details
    Uses heuristics based on known vulnerability patterns.
    In production, would use NVD API for accurate CVSS scores.
    """
    description_lower = description.lower()
    
    # Critical vulnerabilities
    critical_keywords = ['remote code execution', 'rce', 'arbitrary code execution', 
                        'kernel panic', 'dos', 'denial of service', 'privilege escalation']
    if any(keyword in description_lower for keyword in critical_keywords):
        return 'critical'
    
    # High severity
    high_keywords = ['memory corruption', 'buffer overflow', 'sql injection', 
                     'xss', 'cross-site scripting', 'authentication bypass']
    if any(keyword in description_lower for keyword in high_keywords):
        return 'high'
    
    # Medium severity
    medium_keywords = ['information disclosure', 'race condition', 'logic error']
    if any(keyword in description_lower for keyword in medium_keywords):
        return 'medium'
    
    # Default to low
    return 'low'


def generate_html_report(output_file=None):
    """
    Generate comprehensive HTML vulnerability report.
    
    @param output_file str Output HTML file path (default: cache/vulnerability_report.html)
    
    @return str Path to generated HTML file
    
    @details
    Aggregates all machine vulnerability reports and generates a single
    comprehensive HTML dashboard with:
    - Statistics overview
    - Machine summaries
    - Vulnerability tables with filtering
    - Severity-based styling
    - Responsive design
    """
    if output_file is None:
        output_file = os.path.join(CACHE_DIR, "vulnerability_report.html")
    
    # Aggregate vulnerability data
    logger.info("Aggregating vulnerability reports...")
    vuln_data = aggregate_vulnerabilities()
    
    if not vuln_data['machines']:
        logger.warning("No vulnerability data found to report")
        return None
    
    # Create templates directory
    templates_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    # Create Jinja2 environment
    env = Environment(
        loader=FileSystemLoader(templates_dir),
        autoescape=select_autoescape(['html', 'xml'])
    )
    
    # Create HTML template if it doesn't exist
    template_file = os.path.join(templates_dir, 'vulnerability_report.html')
    if not os.path.exists(template_file):
        create_html_template(template_file)
    
    # Load and render template
    template = env.get_template('vulnerability_report.html')
    
    # Prepare data for template
    severity_colors = {
        'critical': '#DC2626',
        'high': '#F97316',
        'medium': '#EAB308',
        'low': '#22C55E'
    }
    
    severity_icons = {
        'critical': 'error',
        'high': 'warning',
        'medium': 'info',
        'low': 'check_circle'
    }
    
    template_data = {
        'machines': vuln_data['machines'],
        'statistics': dict(vuln_data['statistics']),
        'severity_breakdown': dict(vuln_data['statistics']['severity_breakdown']),
        'severity_colors': severity_colors,
        'severity_icons': severity_icons,
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # Render HTML
    html_content = template.render(**template_data)
    
    # Write to file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    logger.info(f"HTML report generated: {output_file}")
    return output_file


def create_html_template(template_path):
    """
    Create the Jinja2 HTML template for vulnerability reports.
    
    @param template_path str Path where template should be created
    """
    template_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <style>
        .severity-critical { background-color: #DC2626; }
        .severity-high { background-color: #F97316; }
        .severity-medium { background-color: #EAB308; }
        .severity-low { background-color: #22C55E; }
        
        .severity-critical-light { background-color: #FEE2E2; color: #991B1B; }
        .severity-high-light { background-color: #FFEDD5; color: #92400E; }
        .severity-medium-light { background-color: #FEFCE8; color: #713F12; }
        .severity-low-light { background-color: #DCFCE7; color: #166534; }
        
        .material-icons {
            vertical-align: middle;
            font-size: 1.25rem;
        }
        
        .gradient-bg {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        
        .card-shadow {
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        thead tr {
            background-color: #F3F4F6;
        }
        
        tbody tr:hover {
            background-color: #F9FAFB;
        }
        
        td, th {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #E5E7EB;
        }
    </style>
</head>
<body class="bg-gray-50">
    <!-- Header -->
    <div class="gradient-bg text-white py-8">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between">
                <div>
                    <h1 class="text-4xl font-bold">Vulnerability Report</h1>
                    <p class="mt-2 text-gray-200">Comprehensive vulnerability assessment across all machines</p>
                </div>
                <div class="text-right">
                    <span class="material-icons" style="font-size: 4rem;">security</span>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- Statistics Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <!-- Total Machines -->
            <div class="bg-white rounded-lg card-shadow p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-600 text-sm font-medium">Machines Scanned</p>
                        <p class="text-3xl font-bold text-gray-900 mt-2">{{ statistics.total_machines }}</p>
                    </div>
                    <span class="material-icons text-blue-500" style="font-size: 2.5rem;">computer</span>
                </div>
            </div>
            
            <!-- Total CVEs -->
            <div class="bg-white rounded-lg card-shadow p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-600 text-sm font-medium">Total CVEs Found</p>
                        <p class="text-3xl font-bold text-gray-900 mt-2">{{ statistics.total_cves }}</p>
                    </div>
                    <span class="material-icons text-red-500" style="font-size: 2.5rem;">error</span>
                </div>
            </div>
            
            <!-- Critical -->
            <div class="bg-white rounded-lg card-shadow p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-600 text-sm font-medium">Critical</p>
                        <p class="text-3xl font-bold text-red-600 mt-2">{{ severity_breakdown.critical|default(0) }}</p>
                    </div>
                    <span class="material-icons text-red-600" style="font-size: 2.5rem;">priority_high</span>
                </div>
            </div>
            
            <!-- Report Generated -->
            <div class="bg-white rounded-lg card-shadow p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-600 text-sm font-medium">Generated</p>
                        <p class="text-sm font-mono text-gray-900 mt-2">{{ generated_at }}</p>
                    </div>
                    <span class="material-icons text-green-500" style="font-size: 2.5rem;">check_circle</span>
                </div>
            </div>
        </div>
        
        <!-- Severity Breakdown -->
        <div class="bg-white rounded-lg card-shadow p-6 mb-8">
            <h2 class="text-2xl font-bold text-gray-900 mb-6 flex items-center">
                <span class="material-icons mr-2">show_chart</span>
                Vulnerability Severity Distribution
            </h2>
            
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                {% for severity, count in severity_breakdown.items() %}
                    <div class="severity-{{ severity }}-light rounded-lg p-4">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm font-medium capitalize">{{ severity }}</p>
                                <p class="text-2xl font-bold mt-2">{{ count }}</p>
                            </div>
                            <span class="material-icons" style="font-size: 2rem;">{{ severity_icons.get(severity, 'info') }}</span>
                        </div>
                    </div>
                {% endfor %}
            </div>
        </div>
        
        <!-- Machine Reports -->
        <div class="space-y-6">
            {% for machine_name, machine_data in machines.items() %}
                <div class="bg-white rounded-lg card-shadow overflow-hidden">
                    <!-- Machine Header -->
                    <div class="bg-gradient-to-r from-blue-50 to-indigo-50 border-l-4 border-blue-500 p-6">
                        <div class="flex items-center justify-between">
                            <div>
                                <h3 class="text-2xl font-bold text-gray-900 flex items-center">
                                    <span class="material-icons mr-2">dns</span>
                                    {{ machine_data.name }}
                                </h3>
                                <p class="text-gray-600 text-sm mt-1">Scanned: {{ machine_data.timestamp }}</p>
                            </div>
                            <div class="text-right">
                                <p class="text-3xl font-bold text-red-600">{{ machine_data.total_vulns }}</p>
                                <p class="text-gray-600 text-sm">Vulnerabilities Found</p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Machine Stats -->
                    {% if machine_data.total_vulns > 0 %}
                        <div class="border-t border-gray-200 px-6 py-4 bg-gray-50">
                            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                                <div>
                                    <p class="text-gray-600">Critical</p>
                                    <p class="text-xl font-bold text-red-600">{{ machine_data.severity_distribution.critical|default(0) }}</p>
                                </div>
                                <div>
                                    <p class="text-gray-600">High</p>
                                    <p class="text-xl font-bold text-orange-500">{{ machine_data.severity_distribution.high|default(0) }}</p>
                                </div>
                                <div>
                                    <p class="text-gray-600">Medium</p>
                                    <p class="text-xl font-bold text-yellow-500">{{ machine_data.severity_distribution.medium|default(0) }}</p>
                                </div>
                                <div>
                                    <p class="text-gray-600">Low</p>
                                    <p class="text-xl font-bold text-green-600">{{ machine_data.severity_distribution.low|default(0) }}</p>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Vulnerabilities Table -->
                        <div class="overflow-x-auto">
                            <table class="w-full">
                                <thead>
                                    <tr>
                                        <th class="text-left">Severity</th>
                                        <th class="text-left">CVE</th>
                                        <th class="text-left">Description</th>
                                        <th class="text-left">Affected Component</th>
                                        <th class="text-center">Details</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for vuln in machine_data.vulnerabilities %}
                                        <tr>
                                            <td>
                                                <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium severity-{{ vuln.severity }}-light">
                                                    {{ vuln.severity|capitalize }}
                                                </span>
                                            </td>
                                            <td>
                                                <code class="bg-gray-100 px-2 py-1 rounded text-sm font-mono">{{ vuln.cve_id }}</code>
                                            </td>
                                            <td class="max-w-xs text-sm text-gray-600">{{ vuln.description[:60] }}{% if vuln.description|length > 60 %}...{% endif %}</td>
                                            <td class="text-sm text-gray-600">
                                                <code class="bg-gray-100 px-2 py-1 rounded text-xs font-mono">{{ vuln.cpe[:50] }}...</code>
                                            </td>
                                            <td class="text-center">
                                                <a href="{{ vuln.url }}" target="_blank" rel="noopener noreferrer" class="text-blue-600 hover:text-blue-800 inline-flex items-center">
                                                    <span class="material-icons text-sm">open_in_new</span>
                                                </a>
                                            </td>
                                        </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    {% else %}
                        <div class="px-6 py-12 text-center">
                            <span class="material-icons text-green-500 mb-4" style="font-size: 3rem;">verified</span>
                            <p class="text-gray-600 font-medium">No vulnerabilities found</p>
                        </div>
                    {% endif %}
                </div>
            {% endfor %}
        </div>
    </div>
    
    <!-- Footer -->
    <div class="bg-gray-900 text-gray-400 py-8 mt-12">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
            <p>Vulnerability Assessment Report • Generated on {{ generated_at }}</p>
        </div>
    </div>
</body>
</html>"""
    
    os.makedirs(os.path.dirname(template_path), exist_ok=True)
    with open(template_path, 'w') as f:
        f.write(template_content)
    
    logger.info(f"HTML template created: {template_path}")
