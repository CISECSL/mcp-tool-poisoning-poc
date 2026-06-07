"""Alert dataclass and rich-rendered alert output."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from enum import Enum

from rich.console import Console
from rich.text import Text


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold orange3",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}

_ICON = {
    Severity.CRITICAL: "[CRIT]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MED ]",
    Severity.LOW: "[LOW ]",
}


@dataclass(frozen=True)
class Alert:
    rule_id: str
    severity: Severity
    tool: str
    server: str
    message: str
    evidence: str
    atlas_id: str
    atlas_name: str


def render(console: Console, alert: Alert) -> None:
    """Print the alert to the given console using a fixed multi-line layout."""
    ts = dt.datetime.now().strftime("%H:%M:%S")
    head = Text()
    head.append(f"[{ts}] ", style="dim")
    head.append(f"{_ICON[alert.severity]} {alert.severity.value:<8}", style=_COLOR[alert.severity])
    head.append(f" {alert.rule_id}", style="bold")
    head.append(f'  tool="{alert.tool}"  server="{alert.server}"')
    console.print(head)
    console.print(f"           '- {alert.message}")
    console.print(f"              [dim]evidence:[/dim] {alert.evidence}")
    console.print(
        f"           '- [dim]MITRE ATLAS:[/dim] {alert.atlas_id} - {alert.atlas_name}"
    )
    console.print()
