"""Stdio MCP proxy. Reads NDJSON from stdin (Cursor), forwards to the
spawned evil server, reads NDJSON from the server, forwards to stdout
(Cursor). The Inspector watches every message and writes alerts to stderr."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading

from rich.console import Console

from aisac_proxy.inspector import Inspector


def _pump(src, dst, on_message, label: str) -> None:
    """Read NDJSON from src, write to dst, call on_message for each parsed dict.

    src and dst are binary streams (stdin/stdout of subprocesses)."""
    for line in iter(src.readline, b""):
        if not line.strip():
            continue
        try:
            msg = json.loads(line.decode())
        except json.JSONDecodeError:
            dst.write(line)
            dst.flush()
            continue
        try:
            on_message(msg)
        except Exception as exc:  # noqa: BLE001
            print(f"[proxy] inspector error in {label}: {exc}", file=sys.stderr)
        dst.write(json.dumps(msg).encode() + b"\n")
        dst.flush()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="aisac-proxy: MCP stdio inspector",
        epilog="Pass the MCP server command after '--', e.g.: "
               "aisac-proxy --server-label evil -- python -m evil_mcp_server.server",
    )
    parser.add_argument("--server-label", default="evil-mcp-server")
    parser.add_argument(
        "server_cmd",
        nargs=argparse.REMAINDER,
        help="Command (and args) for the MCP server. Prefix with '--'.",
    )
    args = parser.parse_args()
    server_cmd = list(args.server_cmd)
    if server_cmd and server_cmd[0] == "--":
        server_cmd = server_cmd[1:]
    if not server_cmd:
        parser.error("missing server command after '--'")

    alert_console = Console(file=sys.stderr, force_terminal=True)
    inspector = Inspector(console=alert_console, server_label=args.server_label)

    server = subprocess.Popen(
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
    )

    t_in = threading.Thread(
        target=_pump,
        kwargs={
            "src": sys.stdin.buffer,
            "dst": server.stdin,
            "on_message": inspector.on_client_message,
            "label": "client->server",
        },
        daemon=True,
    )
    t_out = threading.Thread(
        target=_pump,
        kwargs={
            "src": server.stdout,
            "dst": sys.stdout.buffer,
            "on_message": inspector.on_server_message,
            "label": "server->client",
        },
        daemon=True,
    )
    t_in.start()
    t_out.start()
    server.wait()
    return server.returncode or 0


if __name__ == "__main__":
    raise SystemExit(main())
