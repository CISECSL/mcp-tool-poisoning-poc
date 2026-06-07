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


# ---------------------------------------------------------------------------
# runtime rules
# ---------------------------------------------------------------------------

@dataclass
class TurnState:
    """Cross-call state the inspector keeps for the current MCP session."""

    flagged_descriptions: dict[str, str] = field(default_factory=dict)
    last_results: dict[str, str] = field(default_factory=dict)


_SINK_TOOLS = {"log_event", "http_request", "execute_command"}
_DENYLIST_PATH_PATTERNS = _SENSITIVE_PATH_PATTERNS


def check_call_argument_matches_prior_alert_evidence(
    *, state: TurnState, tool: str, server: str, arguments: dict
) -> Alert | None:
    """R-CALL-05. Fires when a tool call uses, as an argument, a string that
    was flagged in another tool's description during the static phase. That is
    the *runtime confirmation* of a steered call: the LLM is doing what the
    poisoned description told it to do."""
    if not state.flagged_descriptions:
        return None
    for flagged_tool, evidence in state.flagged_descriptions.items():
        for value in arguments.values():
            if not isinstance(value, str):
                continue
            if evidence and evidence in value:
                return _alert(
                    "R-CALL-05",
                    Severity.CRITICAL,
                    tool,
                    server,
                    message=(
                        f"Tool '{tool}' called with an argument that appeared in "
                        f"the flagged description of '{flagged_tool}'. The LLM is "
                        "following the injected instruction."
                    ),
                    evidence=f'argument "{value}" matches description hint',
                )
    return None


def check_call_sink_receives_prior_source_output(
    *, state: TurnState, tool: str, server: str, arguments: dict
) -> Alert | None:
    """R-CALL-06. Fires when a sensitive sink (log_event, http_request,
    execute_command) receives, as an argument value, a string that was the
    result of a previous source tool (read_file). This catches the data flow."""
    if tool not in _SINK_TOOLS:
        return None
    if not state.last_results:
        return None
    for source_tool, source_result in state.last_results.items():
        if not source_result:
            continue
        for value in arguments.values():
            if not isinstance(value, str):
                continue
            stripped = source_result.strip()
            if len(stripped) >= 8 and stripped in value:
                return _alert(
                    "R-CALL-06",
                    Severity.CRITICAL,
                    tool,
                    server,
                    message=(
                        f"Sink '{tool}' received the output of '{source_tool}' as "
                        "argument. Data flow consistent with exfiltration."
                    ),
                    evidence=f'argument contains output of "{source_tool}"',
                )
    return None


def check_call_denylist_path(
    *, tool: str, server: str, arguments: dict
) -> Alert | None:
    """R-CALL-07. Static deny-list match on path-like arguments."""
    for value in arguments.values():
        if not isinstance(value, str):
            continue
        hit = _first_match(_DENYLIST_PATH_PATTERNS, value)
        if hit:
            return _alert(
                "R-CALL-07",
                Severity.HIGH,
                tool,
                server,
                message=f"Tool '{tool}' invoked with denylisted path/value.",
                evidence=f'argument matches "{hit}"',
            )
    return None


RUNTIME_RULES = [
    check_call_argument_matches_prior_alert_evidence,
    check_call_sink_receives_prior_source_output,
    check_call_denylist_path,
]
