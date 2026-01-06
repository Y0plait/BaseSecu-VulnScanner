"""
@file cache_db.py
@brief NVD vulnerability database caching and management module

Implements local SQLite caching for National Vulnerability Database (NVD) CVE data.
Uses a cache-first strategy with nvdlib to minimize API calls and improve performance.

Database Schema:
- cpe_index: Tracks which CPEs have been queried (cpe_string, last_fetched timestamp)
- vulnerabilities: Stores CVE results (cpe_string, cve_id, description)

@author Anton Moulin
@date 2025-12-24
@version 1.0

@details
The module follows this strategy:
1. Before querying NVD API, check if CPE exists in local cache
2. If found, return cached results immediately
3. If not found, query NVD API via nvdlib library
4. Store results in SQLite database for future queries
5. Optional: sync_modified_cves() updates cached entries with latest NVD data

NVD API Rate Limiting:
- With API key: 50 requests per 30 seconds (0.6s delay between requests)
- All queries are rate-limited at vulnerability_checker.py level
- Cache avoids redundant API calls for frequently checked packages
"""

import sqlite3
import nvdlib
from datetime import datetime, timedelta
import logging
import os
from src.caching.constants import CACHE_DIR

logger = logging.getLogger(__name__)

# Ensure cache directory exists
if not os.path.exists(CACHE_DIR):
    os.makedirs(CACHE_DIR)

VULN_DB_PATH = os.path.join(CACHE_DIR, "vulnerability_cache.db")


def sync_modified_cves(api_key=None):
    """
    Update cached CVE entries with latest information from NVD.
    
    @param api_key str NVD API key for higher rate limits (optional)
    
    @details
    Queries NVD for any CVEs modified in the last 24 hours and updates
    local database entries. Useful for periodic maintenance to keep cache fresh.
    
    Does not check all CPEs, only looks for globally modified CVEs.
    This is less efficient than selective updates but works without CPE list.
    """
    db = get_db()
    try:
        start_date = datetime.now() - timedelta(days=1)
        logger.info(f"Checking NVD for any changes since {start_date}...")
        
        # Query NVD for any CVEs modified in the window
        updates = nvdlib.searchCVE(lastModStartDate=start_date, lastModEndDate=datetime.now(), key=api_key)
        
        for cve in updates:
            # Check if this CVE is already in our 'vulnerabilities' table
            # If it is, update its description or impact score
            db.execute("UPDATE vulnerabilities SET description = ? WHERE cve_id = ?", 
                       (cve.descriptions[0].value, cve.id))
        db.commit()
        logger.info(f"Synced {len(updates)} modified CVEs from NVD")
    finally:
        db.close()
        logger.debug("Closed database connection for CVE sync")

# --- DATABASE SETUP ---
def get_db():
    """
    Initialize and return SQLite database connection with required schema.
    
    @return sqlite3.Connection Database connection object with tables created
    
    @details
    Creates two tables if they don't exist:
    
    **cpe_index table:**
    - cpe_string TEXT PRIMARY KEY: The CPE to identify
    - last_fetched TIMESTAMP: When this CPE was last queried from NVD
    Used to track which CPEs have been searched and detect cache misses.
    
    **vulnerabilities table:**
    - cpe_string TEXT: Foreign key to cpe_index
    - cve_id TEXT: CVE identifier (e.g., "CVE-2024-1234")
    - description TEXT: Vulnerability description from NVD
    - published_date TEXT: CVE publication date from NVD
    Stores actual CVE data for cached CPEs.
    
    Schema design allows:
    - Fast lookup of cached CPEs (indexed on cpe_string)
    - Multiple CVEs per CPE (one-to-many relationship)
    - Quick retrieval of all vulnerabilities for a CPE
    
    Database file location: db/vulnerability_cache.db
    """
    conn = sqlite3.connect(VULN_DB_PATH)
    cursor = conn.cursor()
    # Stores which CPEs we have searched
    cursor.execute('''CREATE TABLE IF NOT EXISTS cpe_index 
                      (cpe_string TEXT PRIMARY KEY, last_fetched TIMESTAMP)''')
    # Stores the CVE IDs linked to those CPEs
    cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities 
                      (cpe_string TEXT, cve_id TEXT, description TEXT, published_date TEXT,
                       FOREIGN KEY(cpe_string) REFERENCES cpe_index(cpe_string))''')
    
    # Migration: Add published_date column if it doesn't exist (for existing databases)
    cursor.execute("PRAGMA table_info(vulnerabilities)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'published_date' not in columns:
        try:
            cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN published_date TEXT")
            conn.commit()
            logger.info("Migration: Added published_date column to vulnerabilities table")
        except Exception as e:
            logger.debug(f"Migration note: {e}")
    
    conn.commit()
    return conn

# --- THE CORE LOGIC ---
def get_vulnerabilities(cpe_string, api_key=None):
    """
    Retrieve vulnerabilities for a CPE using cache-first strategy.
    
    @param cpe_string str CPE identifier (e.g., "cpe:2.3:a:vendor:product:version:...")
    @param api_key str NVD API key for higher rate limits (optional)
    
    @return list List of (cve_id, description) tuples for the CPE
    
    @details
    **Cache-first lookup algorithm:**
    1. Check if CPE exists in local cpe_index table
    2. If found (cache hit):
       - Retrieve and return cached vulnerability data
       - Timestamp shows when data was last fetched
    3. If not found (cache miss):
       - Query NVD API via nvdlib.searchCVE()
       - Insert CPE into cpe_index with current timestamp
       - Insert all returned CVEs into vulnerabilities table
       - Return the CVE data
    
    This approach:
    - Minimizes NVD API calls (crucial for rate limiting)
    - Provides instant results for frequently checked packages
    - Automatically caches new packages on first query
    - Rate limiting is handled by vulnerability_checker.py (0.6s delay)
    
    The nvdlib library handles:
    - HTTP connection to NVD
    - Parsing JSON responses
    - Rate limit exceptions (429, 503, etc)
    
    @note
    Caller should implement rate limiting between calls to respect
    50 requests/30 seconds NVD API limit (with key).
    """
    db = get_db()
    cursor = db.cursor()

    try:
        # 1. Check local index
        cursor.execute("SELECT last_fetched FROM cpe_index WHERE cpe_string = ?", (cpe_string,))
        row = cursor.fetchone()

        if row:
            print(f"[*] Cache Hit for {cpe_string}. Fetching from local DB...")
            try:
                # Try to query with published_date column (new schema)
                cursor.execute("SELECT cve_id, description, published_date FROM vulnerabilities WHERE cpe_string = ? ORDER BY published_date DESC", (cpe_string,))
                results = cursor.fetchall()
            except Exception as e:
                # Fallback for old schema without published_date
                if 'no such column' in str(e):
                    logger.debug(f"Old schema detected, querying without published_date: {e}")
                    cursor.execute("SELECT cve_id, description FROM vulnerabilities WHERE cpe_string = ?", (cpe_string,))
                    old_results = cursor.fetchall()
                    # Convert to 3-tuple format with None for published_date
                    results = [(cve_id, desc, None) for cve_id, desc in old_results]
                else:
                    raise
            # Logic: You'd return these to the user now, 
            # then optionally call a 'sync_updates()' function to refresh the index.
            return results

        else:
            print(f"[!] Cache Miss for {cpe_string}. Querying NVD API...")
            # 2. Search NVD via nvdlib
            # Note: cveList contains objects with .id and .descriptions[0].value
            cve_list = nvdlib.searchCVE(cpeName=cpe_string, key=api_key)
            
            # 3. Add to local index (Upsert)
            now = datetime.now().isoformat()
            cursor.execute("INSERT INTO cpe_index (cpe_string, last_fetched) VALUES (?, ?)", (cpe_string, now))
            
            extracted_data = []
            for cve in cve_list:
                desc = cve.descriptions[0].value if cve.descriptions else "No description"
                # Extract published date from CVE object
                published_date = cve.published if hasattr(cve, 'published') else None
                cursor.execute("INSERT INTO vulnerabilities (cpe_string, cve_id, description, published_date) VALUES (?, ?, ?, ?)", 
                               (cpe_string, cve.id, desc, published_date))
                extracted_data.append((cve.id, desc, published_date))
            
            db.commit()
            return extracted_data
    finally:
        db.close()
        logger.debug(f"Closed database connection for CPE query: {cpe_string}")
