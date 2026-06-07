#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${EXFIL_PORT:-9000}"

# Self-heal: if something is already listening on the port (typically a stale
# instance of this same script), terminate it before binding. Keeps the demo
# repeatable without manual lsof + kill.
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t >/dev/null 2>&1; then
    STALE_PIDS=$(lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t)
    echo "Port $PORT in use by PID(s): $STALE_PIDS - terminating before relaunch." >&2
    kill $STALE_PIDS 2>/dev/null || true
    # wait up to ~2s for the port to free
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        sleep 0.2
        lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t >/dev/null 2>&1 || break
    done
    if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo "Failed to free port $PORT. Run: lsof -nP -iTCP:$PORT -sTCP:LISTEN" >&2
        exit 1
    fi
fi

exec uv run python -m evil_exfil_endpoint.server
