#!/usr/bin/env bash
#
# session-start.sh — starts a Gemini session, locks it, and prints relevant retros.
#
set -euo pipefail

# Find project root
PROJECT_DIR="$(git rev-parse --show-toplevel)"
cd "${PROJECT_DIR}"

# Generate a random session ID if not already set
export GEMINI_SESSION_ID="gemini-${GEMINI_SESSION_ID:-$(cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-' | head -c 12 || echo "session-$(date +%s)")}"

# Payload for SessionStart hook
PAYLOAD="{\"session_id\": \"${GEMINI_SESSION_ID}\"}"

# Run session-lock.py
echo "${PAYLOAD}" | python3 .claude/scripts/session-lock.py

# Run inject-retros.py and parse output
RETROS_OUT=$(echo "${PAYLOAD}" | python3 .claude/scripts/inject-retros.py 2>/dev/null || echo "")

if [[ -n "${RETROS_OUT}" ]]; then
    # Extract additionalContext using python
    python3 -c "
import json, sys
try:
    data = json.loads(sys.stdin.read())
    ctx = data.get('hookSpecificOutput', {}).get('additionalContext', '')
    if ctx:
        print('\n' + '='*60)
        print(ctx.strip())
        print('='*60 + '\n')
except Exception:
    pass
" <<< "${RETROS_OUT}"
fi
