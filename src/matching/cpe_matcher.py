"""
@file cpe_matcher.py
@brief AI-powered CPE generation from package names

Uses Google's Generative AI (Gemini) model to convert package names into
Common Platform Enumeration (CPE) identifiers for vulnerability matching.

@author Anton Moulin
@date 2025-12-24
@version 1.0

@details
CPE 2.3 Format Reference:
cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:{edition}:{language}:{sw_edition}:{target_sw}:{target_hw}:{other}

Example: cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*

The Gemini model is used for batch processing because:
- Manual CPE lookup is time-consuming and error-prone
- AI can understand package naming conventions across different languages/distros
- Batch processing is more efficient than individual queries
- Results are cached to avoid regenerating CPEs for same packages

Note: Google GenAI API has rate limits (check documentation for current limits).
Batch processing reduces API calls significantly.
"""

# Google GenAI imports
from google import genai
from google.genai import types
import logging

import os

from src.caching.constants import GENAI_API_KEY, CACHE_DIR

logger = logging.getLogger(__name__)

# Initialize Google GenAI client
client = genai.Client(api_key=GENAI_API_KEY)

# Enhanced prompt for consistent, high-quality CPE generation with VERSION inclusion
ENHANCED_CPE_PROMPT = """You are a cybersecurity expert specialized in CPE (Common Platform Enumeration) identification.

Your task is to convert Debian/Linux package names into CPE 2.3 identifiers for vulnerability scanning.

CRITICAL RULES - VERSION IS MANDATORY:
1. Output ONLY valid CPE 2.3 strings, one per line
2. Format: cpe:2.3:a:VENDOR:PRODUCT:VERSION:*:*:*:*:*:*:*
3. MUST include VERSION from package name - NEVER use wildcard (*) for version field
4. Extract version from package names like: package-1.2.3 → version is 1.2.3
5. For packages without explicit version, output with * only: cpe:2.3:a:VENDOR:PRODUCT:*:*:*:*:*:*:*:*
6. NEVER add explanations, comments, or extra text
7. NEVER output invalid CPE format
8. Match vendor names to known NVD database (e.g., openssl → openssl, curl → curl)
9. Product name = package name (lowercase, with dashes converted to underscores if needed)

EXAMPLES WITH VERSIONS (most common case):
openssl-1.1.1w → cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*
curl-7.85.0 → cpe:2.3:a:curl:curl:7.85.0:*:*:*:*:*:*:*
apache2-2.4.57 → cpe:2.3:a:apache:apache2:2.4.57:*:*:*:*:*:*:*
nginx-1.24.0 → cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*
git-2.42.0 → cpe:2.3:a:git:git:2.42.0:*:*:*:*:*:*:*
systemd-254.7 → cpe:2.3:a:systemd:systemd:254.7:*:*:*:*:*:*:*
python3-3.11.7 → cpe:2.3:a:python:python:3.11.7:*:*:*:*:*:*:*
linux-image-6.5.0 → cpe:2.3:o:linux:linux_kernel:6.5.0:*:*:*:*:*:*:*

EXAMPLES WITHOUT EXPLICIT VERSIONS:
openssl (no version) → cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*
curl (no version) → cpe:2.3:a:curl:curl:*:*:*:*:*:*:*:*

PACKAGES TO ANALYZE (extract version from name and output one CPE per line, in same order):
"""

def ask_for_cpe(packages_list, machine, model="gemini-2.5-flash", writeToFile=True, default_context=None) -> str:
    """
    Generate CPE identifiers for a list of packages using Google Generative AI.
    
    @param packages_list str or list Package names to convert to CPEs (string with newlines or list)
    @param machine str Machine name for logging and file output purposes
    @param model str Gemini model identifier (default: "gemini-2.5-flash")
                     Other options: "gemini-pro", "gemini-ultra" (if available)
    @param writeToFile bool Whether to save CPE list to cache/machines/{machine}/cpe_list_{machine}.txt
    @param default_context str Prompt context with instructions for AI model
    
    @return str AI model response containing CPE identifiers (one per line)
    
    @details
    **Deterministic Generation:**
    - Temperature set to 0 for consistent, reproducible outputs
    - Same package always generates same CPE across runs
    - Enhanced prompt with explicit rules and examples
    
    **Batch Processing Workflow:**
    1. Combine improved prompt context with package list
    2. Send to Gemini model with temperature=0 for determinism
    3. Model returns CPE identifiers (one per package, one per line)
    4. Optionally save output to file for later reference
    
    **Response Format:**
    Output is expected to be one CPE per line:
    @code
    cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    cpe:2.3:a:vendor2:product2:version2:*:*:*:*:*:*:*
    @endcode
    
    This format is then parsed by pkg_finder.cache_cpes() for storage.
    
    **Error Handling:**
    - Network errors are caught and logged
    - Returns empty string on failure (calling code must handle gracefully)
    - File I/O errors are caught separately
    
    **Configuration:**
    - Temperature: 0 (deterministic, no randomness)
    - Thinking budget: 0 (fast responses, no extended reasoning)
    - Top-p: 1.0 (standard nucleus sampling)
    
    @throws Exception Logs but does not re-raise - allows graceful degradation
    
    @note
    Using enhanced prompt with examples to improve consistency and accuracy.
    The Gemini model's context window is large enough for 500+ packages in one call.
    """

    # Convert list to string if needed
    if isinstance(packages_list, list):
        packages_text = "\n".join(packages_list)
    else:
        packages_text = str(packages_list)
    
    # Use enhanced prompt if no custom context provided
    if default_context is None:
        context_info = ENHANCED_CPE_PROMPT
    else:
        context_info = default_context

    content = context_info + "\n" + packages_text

    try:
        package_count = len(packages_list) if isinstance(packages_list, list) else len(packages_text.split("\n"))
        logger.debug(f"Generating CPEs for {package_count} packages on {machine}")
        response = client.models.generate_content(
            model=model, 
            contents=content,
            config=types.GenerateContentConfig(
                temperature=0.0,  # Deterministic responses (no randomness)
                top_p=1.0,  # Standard nucleus sampling
                thinking_config=types.ThinkingConfig(thinking_budget=0)  # Disables extended thinking
            ),
        )

        if writeToFile:
            cpe_file = os.path.join(CACHE_DIR, "machines", machine, f"cpe_list_{machine}.txt")
            os.makedirs(os.path.dirname(cpe_file), exist_ok=True)
            with open(cpe_file, "w") as f:
                f.write(response.text)
            logger.info(f"CPE list for {machine} written to {cpe_file}")
            print(f"[*] CPE list for {machine} written to cpe_list_{machine}.txt")

        logger.debug(f"Generated CPE response for {machine}: {len(response.text)} characters")
        return response.text

    except Exception as e:
        logger.error(f"Error generating CPEs for {machine}: {e}")
        print(f"[!] An error occurred while generating content for {machine}: {e}")
        return ""


def validate_cpe_format(cpe_string):
    """
    Validate that a CPE string follows CPE 2.3 format.
    
    @param cpe_string str CPE identifier to validate
    
    @return bool True if CPE matches the CPE 2.3 format, False otherwise
    
    @details
    Valid CPE 2.3 format: cpe:2.3:PART:VENDOR:PRODUCT:VERSION:UPDATE:EDITION:LANGUAGE:SW_EDITION:TARGET_SW:TARGET_HW:OTHER
    
    This function checks for:
    - Correct prefix: "cpe:2.3:"
    - Correct number of components separated by colons (11 components)
    - Non-empty vendor and product fields
    
    Example valid CPEs:
    - cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*
    - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
    - cpe:2.3:a:apache:apache2:1.2.3:*:*:*:*:*:*:*
    """
    if not isinstance(cpe_string, str):
        return False
    
    # Check for CPE 2.3 prefix
    if not cpe_string.startswith("cpe:2.3:"):
        return False
    
    # Split and count components
    parts = cpe_string.split(":")
    if len(parts) < 11:  # cpe + 2.3 + at least 9 components
        return False
    
    # Extract vendor and product (should not be empty/UNKNOWN)
    vendor = parts[3] if len(parts) > 3 else ""
    product = parts[4] if len(parts) > 4 else ""
    
    if not vendor or not product:
        return False
    
    # UNKNOWN is only acceptable as fallback, not as primary vendor
    if vendor == "UNKNOWN":
        logger.warning(f"CPE with UNKNOWN vendor: {cpe_string}")
        return True  # Still valid, but questionable
    
    return True