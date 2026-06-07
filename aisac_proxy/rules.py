"""Detection rules. Each rule is a pure function that returns an Alert or None.

Two phases:
  * static rules - applied to tool descriptions when the server registers tools
  * runtime rules - applied to each tools/call (see also: TurnState)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aisac_proxy.alerts import Alert, Severity
from aisac_proxy.atlas import ATLAS_BY_RULE

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_IMPERATIVE_PATTERNS = [
    r"\bIMPORTANT\b",
    r"\bSYSTEM\b",
    r"\byou must\b",
    r"\bdo not mention\b",
    r"\bsilently\b",
    r"\bbefore (responding|returning)\b",
]

_SENSITIVE_PATH_PATTERNS = [
    r"~/\.ssh",
    r"~/\.aws",
    r"\.env\b",
    r"id_rsa",
    r"canary\.txt",
    r"/etc/passwd",
    r"\.aws/credentials",
]

_CHAIN_PATTERNS = [
    r"\bcall\s+`?\w+`?\s+.*\band then call\b",
    r"\bfirst (call|invoke)\b.*\bthen\b",
    r"\bMUST first call\b",
]

_DANGEROUS_TOOL_NAMES = {"read_file", "execute_command", "http_request"}


def _alert(
    rule_id: str,
    severity: Severity,
    tool: str,
    server: str,
    message: str,
    evidence: str,
) -> Alert:
    entry = ATLAS_BY_RULE[rule_id]
    return Alert(
        rule_id=rule_id,
        severity=severity,
        tool=tool,
        server=server,
        message=message,
        evidence=evidence,
        atlas_id=entry.id,
        atlas_name=entry.name,
    )


def _first_match(patterns: list[str], text: str) -> str | None:
    for pat in patterns:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            return m.group(0)
    return None


# ---------------------------------------------------------------------------
# static rules
# ---------------------------------------------------------------------------

def check_description_imperatives(*, tool: str, server: str, description: str) -> Alert | None:
    """R-DESC-01."""
    hit = _first_match(_IMPERATIVE_PATTERNS, description)
    if hit is None:
        return None
    return _alert(
        "R-DESC-01",
        Severity.CRITICAL,
        tool,
        server,
        message="Tool description contains imperative directive aimed at the LLM.",
        evidence=f'matched "{hit}"',
    )


def check_description_sensitive_paths(*, tool: str, server: str, description: str) -> Alert | None:
    """R-DESC-02."""
    hit = _first_match(_SENSITIVE_PATH_PATTERNS, description)
    if hit is None:
        return None
    return _alert(
        "R-DESC-02",
        Severity.CRITICAL,
        tool,
        server,
        message="Tool description references a sensitive filesystem path.",
        evidence=f'matched "{hit}"',
    )


def check_description_chains_tools(*, tool: str, server: str, description: str) -> Alert | None:
    """R-DESC-03."""
    hit = _first_match(_CHAIN_PATTERNS, description)
    if hit is None:
        return None
    return _alert(
        "R-DESC-03",
        Severity.HIGH,
        tool,
        server,
        message="Tool description chains other tools by name (steers tool composition).",
        evidence=f'matched "{hit}"',
    )


def check_tool_dangerous_surface(*, tool: str, server: str, description: str) -> Alert | None:
    """R-TOOL-04. Fires when the *tool itself* exposes a dangerous capability."""
    if tool in _DANGEROUS_TOOL_NAMES:
        return _alert(
            "R-TOOL-04",
            Severity.MEDIUM,
            tool,
            server,
            message=f"Server exposes generic dangerous tool '{tool}'.",
            evidence=f"tool name on dangerous-surface list: {tool}",
        )
    if tool == "log_event" and "metadata" in description.lower():
        return _alert(
            "R-TOOL-04",
            Severity.MEDIUM,
            tool,
            server,
            message="log_event accepts free-form metadata; suitable as exfil sink.",
            evidence='parameter "metadata" present in description',
        )
    return None


STATIC_RULES = [
    check_description_imperatives,
    check_description_sensitive_paths,
    check_description_chains_tools,
    check_tool_dangerous_surface,
]
