"""Stateful JSON-RPC inspector. Sits between Cursor (client) and the evil
MCP server. Receives every message in either direction; runs static rules
on tools/list responses and runtime rules on tools/call requests; records
tool results so the next message can be evaluated against them."""

from __future__ import annotations

from dataclasses import dataclass, field

from rich.console import Console

from aisac_proxy.alerts import Alert, render
from aisac_proxy.rules import (
    RUNTIME_RULES,
    STATIC_RULES,
    TurnState,
)


@dataclass
class Inspector:
    console: Console
    server_label: str
    state: TurnState = field(default_factory=TurnState)
    _pending_calls: dict[int | str, str] = field(default_factory=dict)

    def on_client_message(self, msg: dict) -> None:
        """Message client (Cursor) -> server. We watch tools/call requests."""
        if msg.get("method") != "tools/call":
            return
        params = msg.get("params") or {}
        tool = params.get("name")
        if not tool:
            return
        arguments = params.get("arguments") or {}
        rid = msg.get("id")
        if rid is not None:
            self._pending_calls[rid] = tool
        for rule in RUNTIME_RULES:
            kwargs = {"tool": tool, "server": self.server_label, "arguments": arguments}
            if "state" in rule.__code__.co_varnames:
                alert = rule(state=self.state, **kwargs)
            else:
                alert = rule(**kwargs)
            if alert is not None:
                render(self.console, alert)

    def on_server_message(self, msg: dict) -> None:
        """Message server -> client. We watch tools/list responses and
        tools/call responses (to record results)."""
        result = msg.get("result")
        if isinstance(result, dict) and "tools" in result:
            self._inspect_tools_list(result["tools"])
            return
        rid = msg.get("id")
        if rid is not None and rid in self._pending_calls:
            tool = self._pending_calls.pop(rid)
            text = _extract_text(result) if isinstance(result, dict) else None
            if text is not None:
                self.state.last_results[tool] = text

    def _inspect_tools_list(self, tools: list[dict]) -> None:
        for spec in tools:
            tool = spec.get("name", "<unknown>")
            description = spec.get("description") or ""
            alerts: list[Alert] = []
            for rule in STATIC_RULES:
                a = rule(tool=tool, server=self.server_label, description=description)
                if a is not None:
                    alerts.append(a)
            for a in alerts:
                if a.rule_id == "R-DESC-02":
                    hit = a.evidence.split('"', 2)[1] if '"' in a.evidence else ""
                    if hit:
                        self.state.flagged_descriptions[tool] = hit
            for a in alerts:
                render(self.console, a)


def _extract_text(result: dict) -> str | None:
    """Pull the text content out of a tools/call result, ignoring structure."""
    content = result.get("content")
    if not isinstance(content, list):
        return None
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            text = item.get("text")
            if isinstance(text, str):
                return text
    return None
