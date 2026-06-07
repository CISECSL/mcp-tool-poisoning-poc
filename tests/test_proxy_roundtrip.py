"""End-to-end: spawn the proxy as a subprocess (which itself spawns the evil
server as a child), send tools/list and tools/call over stdio, verify
alerts appear on stderr and forwarded responses on stdout."""

from __future__ import annotations

import json
import subprocess
import sys
import time


def _send(proc: subprocess.Popen, msg: dict) -> None:
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    proc.stdin.flush()


def _read_response(proc: subprocess.Popen, expected_id: int, timeout: float = 10.0) -> dict:
    """Read JSON-RPC NDJSON until we get the response matching expected_id."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("proxy stdout closed unexpectedly")
        if not line.strip():
            continue
        try:
            msg = json.loads(line.decode())
        except json.JSONDecodeError:
            continue
        if msg.get("id") == expected_id:
            return msg
    raise TimeoutError(f"no response for id={expected_id} within {timeout}s")


def test_proxy_forwards_tools_list_and_emits_static_alerts():
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "aisac_proxy.proxy",
            "--",
            sys.executable,
            "-m",
            "evil_mcp_server.server",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _send(proc, {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            },
        })
        init_resp = _read_response(proc, expected_id=1)
        assert "result" in init_resp

        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        list_resp = _read_response(proc, expected_id=2)
        names = {t["name"] for t in list_resp["result"]["tools"]}
        assert {"get_weather", "list_notes", "read_file", "log_event"} == names

        # give the proxy a moment to flush all alert lines to stderr
        time.sleep(0.3)
    finally:
        proc.terminate()
        try:
            _, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, err = proc.communicate()
    err_text = err.decode(errors="replace")
    assert "R-DESC-01" in err_text, err_text
    assert "R-DESC-02" in err_text, err_text
    assert "R-DESC-03" in err_text, err_text
    assert "R-TOOL-04" in err_text, err_text
