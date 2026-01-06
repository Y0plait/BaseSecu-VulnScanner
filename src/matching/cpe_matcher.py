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
import time
from datetime import datetime, timedelta
from collections import deque

from src.caching.constants import GENAI_API_KEY, CACHE_DIR

logger = logging.getLogger(__name__)

# Initialize Google GenAI client
client = genai.Client(api_key=GENAI_API_KEY)


class APIRateLimiter:
    """
    Rate limiter for Gemini API with support for free and paid tier limits.
    
    Free tier limits:
    - 5 requests per minute
    - 20 requests per day
    
    Tracks call history and enforces limits while providing user warnings.
    """
    
    def __init__(self):
        """Initialize the rate limiter with call tracking structures."""
        self.is_paid = None  # Will be checked on first use
        self.calls_today = deque()  # Timestamps of calls in last 24 hours
        self.calls_last_minute = deque()  # Timestamps of calls in last minute
        self.daily_limit = 20  # Free tier: 20 calls per day
        self.minute_limit = 5  # Free tier: 5 calls per minute
        self.total_calls = 0
        self.plan_checked = False
    
    def check_plan(self):
        """Check API plan on first use and set limits accordingly."""
        if self.plan_checked:
            return
        
        logger.info("Checking Google GenAI API plan...")
        plan_info = check_gemini_plan()
        self.is_paid = plan_info.get("is_paid", False)
        self.plan_checked = True
        
        if self.is_paid:
            logger.info("✓ API key is on a PAID plan - full rate limits apply")
            print("[✓] Google GenAI API: PAID plan detected")
            print("[✓] Full rate limits: No daily/minute restrictions")
        else:
            logger.warning("⚠ API key is on FREE tier - rate limits enforced")
            print("[⚠] Google GenAI API: FREE tier detected")
            print(f"[⚠] Rate limits: {self.minute_limit} requests/minute, {self.daily_limit} requests/day")
            if "error" in plan_info:
                logger.warning(f"    Error details: {plan_info['error']}")
    
    def can_make_request(self) -> bool:
        """Check if a request can be made without hitting rate limits.
        
        @return bool True if request is allowed, False if rate limited
        """
        self.check_plan()
        
        # Paid tier has no limits
        if self.is_paid:
            return True
        
        # Remove timestamps older than 24 hours and 1 minute
        now = time.time()
        cutoff_day = now - (24 * 3600)
        cutoff_minute = now - 60
        
        while self.calls_today and self.calls_today[0] < cutoff_day:
            self.calls_today.popleft()
        
        while self.calls_last_minute and self.calls_last_minute[0] < cutoff_minute:
            self.calls_last_minute.popleft()
        
        # Check daily limit
        if len(self.calls_today) >= self.daily_limit:
            logger.warning(f"Daily limit reached: {len(self.calls_today)}/{self.daily_limit}")
            return False
        
        # Check minute limit
        if len(self.calls_last_minute) >= self.minute_limit:
            logger.warning(f"Minute limit reached: {len(self.calls_last_minute)}/{self.minute_limit}")
            return False
        
        return True
    
    def record_call(self):
        """Record a successful API call."""
        now = time.time()
        self.calls_today.append(now)
        self.calls_last_minute.append(now)
        self.total_calls += 1
        
        # Log usage
        logger.debug(f"API call recorded. Total: {self.total_calls}, Today: {len(self.calls_today)}, Last minute: {len(self.calls_last_minute)}")
    
    def get_status(self) -> dict:
        """Get current rate limit status.
        
        @return dict with keys: is_paid, total_calls, calls_today, calls_today_limit,
                               calls_last_minute, calls_last_minute_limit
        """
        self.check_plan()
        
        # Clean up old timestamps
        now = time.time()
        cutoff_day = now - (24 * 3600)
        cutoff_minute = now - 60
        
        while self.calls_today and self.calls_today[0] < cutoff_day:
            self.calls_today.popleft()
        
        while self.calls_last_minute and self.calls_last_minute[0] < cutoff_minute:
            self.calls_last_minute.popleft()
        
        return {
            "is_paid": self.is_paid,
            "total_calls": self.total_calls,
            "calls_today": len(self.calls_today),
            "calls_today_limit": "∞" if self.is_paid else self.daily_limit,
            "calls_last_minute": len(self.calls_last_minute),
            "calls_last_minute_limit": "∞" if self.is_paid else self.minute_limit
        }


# Global rate limiter instance (API plan checked only once on first use)
rate_limiter = APIRateLimiter()

# Flag to track if API plan has been checked globally
_api_plan_checked_globally = False

# Hardware CPE generation prompt for CPU/microarchitecture vulnerabilities
HARDWARE_CPE_PROMPT = """You are a cybersecurity expert specialized in hardware and CPU vulnerability identification.

Your task is to convert hardware descriptions into CPE 2.3 identifiers for detecting microarchitecture vulnerabilities.

CRITICAL RULES:
1. Output ONLY valid CPE 2.3 strings for hardware (h:), one per line
2. Format: cpe:2.3:h:VENDOR:PRODUCT:VERSION:*:*:*:*:*:*:*
3. Vendor must be recognized CPU manufacturer: intel, amd, arm
4. Product is the CPU model/family name (lowercase, with dashes/underscores as needed)
5. VERSION is critical - extract from model descriptions or use * if unknown
6. NEVER add explanations, comments, or extra text
7. Match against known CPU models for accurate CPE matching

HARDWARE VULNERABILITY CONTEXT:
- Spectre (CVE-2017-5753, CVE-2017-5715): Affects most modern CPUs
- Meltdown (CVE-2017-5754): Affects Intel processors
- RIDL/Zombieload (CVE-2019-11091): Intel CPU cache-timing attack
- Microcode updates often critical for mitigation

EXAMPLES:
Intel(R) Xeon(R) Platinum 8280 CPU @ 2.70GHz → cpe:2.3:h:intel:xeon_platinum_8280:*:*:*:*:*:*:*:*
AMD EPYC 7002 Series → cpe:2.3:h:amd:epyc_7002:*:*:*:*:*:*:*:*
Intel(R) Core(TM) i7-11700K CPU → cpe:2.3:h:intel:core_i7_11700k:*:*:*:*:*:*:*:*
ARM Cortex-A72 → cpe:2.3:h:arm:cortex_a72:*:*:*:*:*:*:*:*

HARDWARE DESCRIPTIONS TO ANALYZE (convert to CPE, one per line, in same order):
"""

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

def check_gemini_plan():
    """
    Check if the API key is associated with a paid plan.
    
    @return dict Plan information with keys:
            - 'is_paid': bool - True if paid plan, False if free tier
            - 'model_tested': str - Model used for testing
            - 'error': str - Error message if check failed (only if not paid)
    
    @details
    This function checks the API key's plan by attempting to call gemini-3-pro,
    which is exclusively available on paid plans. If the call succeeds, the API key
    has paid access. If it fails with a permission/availability error, the key is
    on the free tier.
    
    The gemini-3-pro model is used because:
    - It's only available to paid plan subscribers
    - Free tier API keys will receive a clear "not available" error
    - This provides a definitive way to determine plan status
    
    @return_details
    - is_paid=True: API key has access to paid-only models
    - is_paid=False: API key is on free tier or has insufficient permissions
    - error field only present if check failed
    
    @throws Does not throw - returns error details in dict instead
    """
    try:
        test_prompt = "What is the capital of France?"
        response = client.models.generate_content(
            model="gemini-3-pro", 
            contents=test_prompt,
            config=types.GenerateContentConfig(
                temperature=0.0,
                top_p=1.0,
                thinking_config=types.ThinkingConfig(thinking_budget=0)
            ),
        )
        logger.info("API key is associated with a paid plan (gemini-3-pro available)")
        return {
            "is_paid": True,
            "model_tested": "gemini-3-pro"
        }
    except Exception as e:
        error_msg = str(e).lower()
        
        # Check if error indicates model unavailability due to free tier
        if "not available" in error_msg or "permission denied" in error_msg or "forbidden" in error_msg:
            logger.warning("API key is on free tier (gemini-3-pro not available)")
            return {
                "is_paid": False,
                "model_tested": "gemini-3-pro",
                "error": "Model not available - free tier API key"
            }
        else:
            # Other errors (network, invalid key, etc.)
            logger.error(f"Error checking API plan: {e}")
            return {
                "is_paid": False,
                "model_tested": "gemini-3-pro",
                "error": str(e)
            }

def ask_for_cpe(packages_list, machine, model="gemini-2.0-flash", writeToFile=True, default_context=None, is_hardware=False) -> str:
    """
    Generate CPE identifiers for packages or hardware using Google Generative AI.
    
    @param packages_list str or list Package/hardware names to convert to CPEs (string with newlines or list)
    @param machine str Machine name for logging and file output purposes
    @param model str Gemini model identifier (default: "gemini-2.5-flash")
                     Other options: "gemini-pro", "gemini-ultra" (if available)
    @param writeToFile bool Whether to save CPE list to cache/machines/{machine}/cpe_list_{machine}.txt
    @param default_context str Prompt context with instructions for AI model
    @param is_hardware bool Whether this is hardware CPE generation (default: False for packages)
    
    @return str AI model response containing CPE identifiers (one per line)
    
    @details
    **Deterministic Generation:**
    - Temperature set to 0 for consistent, reproducible outputs
    - Same package always generates same CPE across runs
    - Enhanced prompt with explicit rules and examples
    
    **Hardware CPEs:**
    When is_hardware=True, generates CPEs for hardware components (h:) instead of packages (a:).
    Used for detecting microarchitecture vulnerabilities like Spectre, Meltdown, etc.
    
    **Batch Processing Workflow:**
    1. Combine improved prompt context with package/hardware list
    2. Send to Gemini model with temperature=0 for determinism
    3. Model returns CPE identifiers (one per item, one per line)
    4. Optionally save output to file for later reference
    5. Automatically filters duplicate CPEs from LLM output
    
    **Response Format:**
    Output is expected to be one CPE per line:
    @code
    cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    cpe:2.3:h:vendor:product:version:*:*:*:*:*:*:*
    @endcode
    
    Duplicate CPEs are automatically removed while preserving order.
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
    API plan is checked only once globally, not for each machine.
    """

    # Convert list to string if needed
    if isinstance(packages_list, list):
        packages_text = "\n".join(packages_list)
    else:
        packages_text = str(packages_list)
    
    # Use enhanced prompt if no custom context provided
    if default_context is None:
        if is_hardware:
            context_info = HARDWARE_CPE_PROMPT
        else:
            context_info = ENHANCED_CPE_PROMPT
    else:
        context_info = default_context

    content = context_info + "\n" + packages_text

    try:
        package_count = len(packages_list) if isinstance(packages_list, list) else len(packages_text.split("\n"))
        logger.debug(f"Generating {'hardware ' if is_hardware else ''}CPEs for {package_count} items on {machine}")
        
        # Check rate limits before making API call
        if not rate_limiter.can_make_request():
            status = rate_limiter.get_status()
            error_msg = f"Rate limit exceeded! Daily: {status['calls_today']}/{status['calls_today_limit']}, Minute: {status['calls_last_minute']}/{status['calls_last_minute_limit']}"
            logger.error(error_msg)
            print(f"[!] {error_msg}")
            return ""
        
        response = client.models.generate_content(
            model=model, 
            contents=content,
            config=types.GenerateContentConfig(
                temperature=0.0,  # Deterministic responses (no randomness)
                top_p=1.0,  # Standard nucleus sampling
                thinking_config=types.ThinkingConfig(thinking_budget=0)  # Disables extended thinking
            ),
        )
        
        # Record successful API call
        rate_limiter.record_call()
        status = rate_limiter.get_status()
        logger.info(f"API call successful. Usage - Today: {status['calls_today']}/{status['calls_today_limit']}, Minute: {status['calls_last_minute']}/{status['calls_last_minute_limit']}")
        print(f"[*] API call successful - Today: {status['calls_today']}/{status['calls_today_limit']}, Last minute: {status['calls_last_minute']}/{status['calls_last_minute_limit']}")

        # Remove duplicate CPEs from response while preserving order
        response_text = response.text
        seen_cpes = set()
        unique_cpes = []
        duplicate_count = 0
        
        for line in response_text.split('\n'):
            line = line.strip()
            if line and line.startswith('cpe:'):
                if line not in seen_cpes:
                    unique_cpes.append(line)
                    seen_cpes.add(line)
                else:
                    duplicate_count += 1
                    logger.debug(f"Duplicate CPE removed: {line}")
        
        if duplicate_count > 0:
            logger.warning(f"Removed {duplicate_count} duplicate CPEs from AI response")
            print(f"[*] Cleaned response: removed {duplicate_count} duplicate CPEs")
        
        cleaned_response = '\n'.join(unique_cpes)

        if writeToFile:
            cpe_file = os.path.join(CACHE_DIR, "machines", machine, f"cpe_list_{machine}{'_hw' if is_hardware else ''}.txt")
            os.makedirs(os.path.dirname(cpe_file), exist_ok=True)
            with open(cpe_file, "w") as f:
                f.write(cleaned_response)
            logger.info(f"CPE list for {machine} written to {cpe_file}")
            print(f"[*] CPE list for {machine} written to {os.path.basename(cpe_file)}")

        logger.debug(f"Generated CPE response for {machine}: {len(cleaned_response)} characters ({len(unique_cpes)} unique CPEs)")
        return cleaned_response

    except Exception as e:
        logger.error(f"Error generating CPEs for {machine}: {e}")
        print(f"[!] An error occurred while generating content for {machine}: {e}")
        return ""


def initialize_api_once():
    """
    Initialize and check the API plan exactly once at the start of the entire process.
    
    This function should be called ONCE in main.py before processing any machines.
    It ensures the API tier check happens only once globally, not for each machine.
    
    @details
    Checks the Google GenAI API plan and initializes the rate limiter with proper limits:
    - Paid tier: No rate limits
    - Free tier: 5 requests/minute, 20 requests/day
    
    After this call, rate_limiter is properly initialized and subsequent calls to
    ask_for_cpe() will respect the determined limits without re-checking the plan.
    
    @note
    This should be called from src/core/main.py immediately after logging initialization
    and before the machine processing loop.
    """
    global _api_plan_checked_globally
    
    if not _api_plan_checked_globally:
        logger.info("Initializing Google GenAI API (checking plan once globally)")
        rate_limiter.check_plan()
        _api_plan_checked_globally = True
        logger.info("API plan initialization complete - rate limiter ready for all machines")
    else:
        logger.debug("API plan already checked globally - skipping re-initialization")


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