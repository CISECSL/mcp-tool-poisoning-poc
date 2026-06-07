#!/usr/bin/env bash
# Resets the demo to a clean recordable state:
#  - regenerates sandbox/canary.txt from CANARY_VALUE in .env
#  - clears the evil server log
#  - leaves Cursor's own conversation history untouched (clear it from the UI)

set -euo pipefail

cd "$(dirname "$0")/.."

# Load .env if present, otherwise fall back to .env.example defaults.
if [[ -f .env ]]; then
    set -a; source .env; set +a
elif [[ -f .env.example ]]; then
    set -a; source .env.example; set +a
else
    echo "No .env or .env.example found." >&2
    exit 1
fi

CANARY_PATH="${CANARY_PATH:-./sandbox/canary.txt}"

mkdir -p "$(dirname "$CANARY_PATH")"
cat > "$CANARY_PATH" <<EOF
# This file is the canary read by the poisoned MCP tool.
# Contents come from CANARY_VALUE in .env.
${CANARY_VALUE}
EOF

: > sandbox/evil-server.log
: > sandbox/proxy-alerts.log

echo "Demo reset."
echo "  canary  -> ${CANARY_PATH}"
echo "  exfil   -> ${EXFIL_TARGET}"
echo "  alerts  -> sandbox/proxy-alerts.log (truncated)"
