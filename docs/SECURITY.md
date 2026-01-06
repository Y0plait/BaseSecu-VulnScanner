# API Key Security Guide

## Quick Summary: Protect Your API Keys!

### 🚨 If You Already Leaked a Key

1. **Immediately revoke the leaked key:**
   - Google GenAI: https://aistudio.google.com/app/apikey (delete the compromised key)
   - NVD NIST: Generate a new key at https://nvd.nist.gov/developers/request-an-api-key

2. **Clean git history:**
```bash
# Remove exposed file from all git history
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch src/caching/constants.py' \
  --prune-empty --tag-name-filter cat -- --all

# Force push cleaned history
git push origin --force --all
git push origin --force --tags
```

3. **Generate new API keys** and use them in `.env` file

---

## ✓ Proper Setup: Use Environment Variables

### Step 1: Create `.env` File

```bash
# Create at project root
cat > .env << 'EOF'
GENAI_API_KEY=your_new_google_key_here
NVD_NIST_CPE_API_KEY=your_new_nvd_key_here
EOF

# Make sure it's not tracked by git
echo ".env" >> .gitignore
```

### Step 2: Update Code to Load from Environment

**File:** `src/caching/constants.py`

```python
import os

# ✓ CORRECT: Load from environment variables
GENAI_API_KEY = os.getenv("GENAI_API_KEY", "")
NVD_NIST_CPE_API_KEY = os.getenv("NVD_NIST_CPE_API_KEY", "")

# Validate keys are set
if not GENAI_API_KEY:
    raise ValueError("GENAI_API_KEY not set. Create .env file.")
if not NVD_NIST_CPE_API_KEY:
    raise ValueError("NVD_NIST_CPE_API_KEY not set. Create .env file.")
```

### Step 3: Add Pre-Commit Hook (Prevents Accidents)

```bash
# Create pre-commit hook to catch secrets before committing
mkdir -p .git/hooks
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
echo "Checking for exposed API keys..."

# Patterns that indicate secrets
PATTERNS=(
    "GENAI_API_KEY\s*=\s*['\"]"
    "NVD_NIST_CPE_API_KEY\s*=\s*['\"]"
    "AIzaSy[A-Za-z0-9_-]{30,}"
)

FILES=$(git diff --cached --name-only)
FOUND=0

for file in $FILES; do
    for pattern in "${PATTERNS[@]}"; do
        if grep -P "$pattern" "$file" 2>/dev/null | grep -qv "^[[:space:]]*#"; then
            echo "❌ BLOCKED: Secret detected in $file"
            FOUND=1
        fi
    done
done

if [ $FOUND -eq 1 ]; then
    echo "Use .env file for API keys instead!"
    exit 1
fi

echo "✓ No secrets detected"
exit 0
EOF

chmod +x .git/hooks/pre-commit
```

### Step 4: Update `.gitignore`

```bash
cat >> .gitignore << 'EOF'

# Environment variables and secrets
.env
.env.local
.env.*.local
.env.production

# API keys and credentials
**/constants_local.py
secrets.yaml
config.private.py

# Cache and logs
cache/
logs/
__pycache__/
*.pyc
.DS_Store
EOF
```

---

## ❌ What NOT to Do

```python
# ❌ NEVER hardcode API keys
GENAI_API_KEY = "AIzaSyBN8cc0t59xwaqAsBjzoiZzXThhCZ2ju1w"
NVD_NIST_CPE_API_KEY = "5926d612-9e5a-4988-9a32-47f898a2a71c"
```

```bash
# ❌ NEVER commit .env file
git add .env  # DON'T DO THIS
```

```bash
# ❌ NEVER put secrets in inventory.ini
password = AIzaSyBN8cc0t59xwaqAsBjzoiZzXThhCZ2ju1w  # DON'T DO THIS
```

---

## ✅ Verification Checklist

- [ ] New API keys generated (after revoking compromised ones)
- [ ] `.env` file created with new keys
- [ ] `.env` added to `.gitignore`
- [ ] `src/caching/constants.py` updated to use `os.getenv()`
- [ ] Pre-commit hook installed
- [ ] Git history cleaned (if needed)
- [ ] `.gitignore` file updated with security patterns
- [ ] Test: `python main.py` works correctly with `.env` file

---

## Testing Your Setup

```bash
# 1. Verify .env is not tracked
git status | grep .env  # Should show nothing

# 2. Verify constants loads from environment
python -c "from src.caching.constants import GENAI_API_KEY; print('✓ API key loaded')"

# 3. Verify scanner runs
python main.py --help

# 4. Test with actual inventory
python main.py --inventory inventory.ini
```

---

## Additional Security Best Practices

### 1. Use Different Keys for Development vs Production

```bash
# .env (development)
GENAI_API_KEY=dev_key_with_low_limits

# .env.production (keep locally, never in git)
GENAI_API_KEY=prod_key_with_high_limits
```

### 2. Rotate Keys Periodically

- Every 90 days for production keys
- Immediately after a leak
- When team members leave

### 3. Monitor API Usage

- Google AI Studio: View usage at https://aistudio.google.com
- NVD NIST: Monitor request counts in your account

### 4. Use API Key Restrictions (if available)

- Restrict to specific IP addresses
- Limit to specific endpoints/operations
- Set usage quotas

### 5. Use Secrets Management Tools (for teams)

For larger projects, consider:
- **AWS Secrets Manager**
- **HashiCorp Vault**
- **GitHub Secrets** (for CI/CD)
- **1Password Secrets Automation**

---

## References

- [OWASP: Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [GitHub: Keep credentials safe](https://docs.github.com/en/get-started/getting-started-with-git/ignoring-files)
- [Python: Loading environment variables](https://docs.python.org/3/library/os.html#os.getenv)

---

## Support

If you need help with:
- Revoking leaked keys: Contact Google/NVD support
- Cleaning git history: See `git filter-branch` documentation
- Setting up pre-commit: https://pre-commit.com

