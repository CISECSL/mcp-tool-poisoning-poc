#!/usr/bin/env bash
# Runs the evil MCP server directly (without the proxy).
# Useful for debugging the server in isolation. The actual demo runs it
# as a subprocess of the proxy.
set -euo pipefail
cd "$(dirname "$0")/.."
exec uv run python -m evil_mcp_server.server
