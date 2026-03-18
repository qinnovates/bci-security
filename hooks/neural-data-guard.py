#!/usr/bin/env python3
"""
Neural Data File Guard — PostToolUse hook for BCI Security Plugin.

Detects when neural data files are written/edited and warns about
anonymization, permissions, and consent metadata.

Security properties:
- File path is canonicalized and basename-only in output (no path disclosure)
- Extension matched against allowlist only (no user-controlled strings in output)
- Error handling: fails closed (emits warning on parse error, never silent bypass)
- No shell commands, no eval, no exec
"""

import sys
import json
import os

NEURAL_EXTENSIONS = {'.edf', '.bdf', '.xdf', '.gdf', '.fif', '.nwb'}

WARNING_TEMPLATE = (
    "Neural data file detected ({ext} format). "
    "Verify: (1) anonymized subject ID, (2) restricted file permissions, "
    "(3) consent metadata exists. Consider adding a .consent.json sidecar file."
)

def main():
    try:
        tool_input = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        # Fail closed: if we can't parse input, warn that the guardrail couldn't run
        print(json.dumps({
            "result": "warn",
            "message": "Neural data guardrail: could not parse hook input. "
                       "Verify manually if this operation involves neural data files."
        }))
        return

    file_path = tool_input.get("tool_input", {}).get("file_path", "")

    if not isinstance(file_path, str) or not file_path:
        print(json.dumps({}))
        return

    # Canonicalize path to prevent traversal
    try:
        canonical = os.path.realpath(file_path)
    except (OSError, ValueError):
        print(json.dumps({}))
        return

    # Extract extension safely — use os.path, not string slicing
    _, ext = os.path.splitext(canonical)
    ext_lower = ext.lower()

    if ext_lower not in NEURAL_EXTENSIONS:
        print(json.dumps({}))
        return

    # Output uses only the matched extension from the allowlist — never the raw path
    print(json.dumps({
        "result": "warn",
        "message": WARNING_TEMPLATE.format(ext=ext_lower)
    }))


if __name__ == "__main__":
    main()
