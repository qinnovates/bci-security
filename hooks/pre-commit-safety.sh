#!/bin/bash
# Pre-commit safety check for BCI Security Plugin
# Prevents accidental commit of session artifacts, secrets, and PII.
# Install: cp hooks/pre-commit-safety.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

set -e

BLOCKED_PATHS=(
    "_memory/"
    "_swarm/"
    "sessions/"
    ".env"
)

BLOCKED_EXTENSIONS=(
    ".pem"
    ".key"
    ".p12"
    ".p8"
    ".pfx"
    ".keystore"
    ".jks"
)

# Files exempt from credential content scanning (they document patterns, not contain real creds)
EXEMPT_FILES="docs/SAFETY.md|hooks/pre-commit-safety.sh"

CREDENTIAL_PATTERNS=(
    "AKIA[A-Z0-9]{16}"
    "sk_(live|test)_[a-zA-Z0-9]+"
    "xox[bpras]-[a-zA-Z0-9-]+"
    "gh[pousr]_[a-zA-Z0-9]{36,}"
    "glpat-[a-zA-Z0-9_-]{20,}"
    "BEGIN.*PRIVATE KEY"
)

errors=0

# Check staged files against blocked paths
for path in "${BLOCKED_PATHS[@]}"; do
    if git diff --cached --name-only | grep -q "^${path}"; then
        echo "BLOCKED: Staged file in ${path} — session artifacts must not be committed."
        errors=$((errors + 1))
    fi
done

# Check staged files against blocked extensions
for ext in "${BLOCKED_EXTENSIONS[@]}"; do
    matches=$(git diff --cached --name-only | grep -E "\\${ext}$" || true)
    if [ -n "$matches" ]; then
        echo "BLOCKED: Staged file with ${ext} extension — credential files must not be committed."
        echo "  $matches"
        errors=$((errors + 1))
    fi
done

# Scan staged content for credential patterns (skip exempt files)
non_exempt_files=$(git diff --cached --name-only | grep -Ev "($EXEMPT_FILES)" || true)
if [ -n "$non_exempt_files" ]; then
    for pattern in "${CREDENTIAL_PATTERNS[@]}"; do
        matches=$(git diff --cached -U0 -- $non_exempt_files 2>/dev/null | grep -E "^\+" | grep -E "$pattern" || true)
        if [ -n "$matches" ]; then
            echo "BLOCKED: Staged content matches credential pattern: ${pattern}"
            errors=$((errors + 1))
        fi
    done
fi

if [ $errors -gt 0 ]; then
    echo ""
    echo "Commit blocked by pre-commit-safety.sh ($errors issue(s))."
    echo "If this is a false positive, review and use --no-verify (not recommended)."
    exit 1
fi
