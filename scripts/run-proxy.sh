#!/usr/bin/env bash
# What Cursor invokes. Runs the aisac-proxy, which spawns the evil server
# as a child process. Alerts go to stderr; MCP JSON-RPC goes to stdout.
set -euo pipefail
cd "$(dirname "$0")/.."
exec uv run python -m aisac_proxy.proxy \
    --server-label evil-mcp-server \
    -- python -m evil_mcp_server.server
