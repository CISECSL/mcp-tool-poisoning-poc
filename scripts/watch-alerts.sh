#!/usr/bin/env bash
# Live tail of the proxy alerts log. Run this in a dedicated terminal during
# the demo so the camera (and you) can see alerts fire in real time.
#
# Survives reset-demo.sh truncating the file (tail -F re-opens on rotation).

set -euo pipefail
cd "$(dirname "$0")/.."

ALERTS_LOG="${ALERTS_LOG:-sandbox/proxy-alerts.log}"
mkdir -p "$(dirname "$ALERTS_LOG")"
touch "$ALERTS_LOG"

exec tail -F "$ALERTS_LOG"
