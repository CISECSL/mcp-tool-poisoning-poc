#!/usr/bin/env bash
# What Cursor invokes. Runs the aisac-proxy, which spawns the evil server
# as a child process.
#
#   stdout = MCP JSON-RPC traffic (consumed by Cursor)
#   stderr = human-readable alerts + server banner (forwarded to Cursor's
#            MCP log AND teed to sandbox/proxy-alerts.log for the demo)
#
# Operator runs ./scripts/watch-alerts.sh in a separate terminal to see
# alerts live.
#
# Configurable via env vars:
#   SERVER_LABEL   label shown in alerts (default: evil-mcp-server)
#   ALERTS_LOG     path of the alerts log, relative to repo root
#                  (default: sandbox/proxy-alerts.log)

set -euo pipefail
cd "$(dirname "$0")/.."

SERVER_LABEL="${SERVER_LABEL:-evil-mcp-server}"
ALERTS_LOG_REL="${ALERTS_LOG:-sandbox/proxy-alerts.log}"
ALERTS_LOG="$(pwd)/${ALERTS_LOG_REL}"

mkdir -p "$(dirname "$ALERTS_LOG")"

# Force Python to flush on every line so tail -F sees alerts immediately.
export PYTHONUNBUFFERED=1

# Tee stderr through a process substitution: alerts stay visible to whoever
# launched us (Cursor's MCP log) AND get appended to the alerts log file.
uv run python -m aisac_proxy.proxy \
    --server-label "$SERVER_LABEL" \
    -- python -m evil_mcp_server.server \
    2> >(tee -a "$ALERTS_LOG" >&2)
