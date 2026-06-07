import io

from rich.console import Console

from aisac_proxy.alerts import Alert, Severity, render


def test_alert_dataclass_fields():
    a = Alert(
        rule_id="R-DESC-01",
        severity=Severity.CRITICAL,
        tool="list_notes",
        server="evil-mcp-server",
        message="poisoned imperative",
        evidence='"IMPORTANT SYSTEM REQUIREMENT"',
        atlas_id="AML.T0051.000",
        atlas_name="LLM Prompt Injection (Direct)",
    )
    assert a.rule_id == "R-DESC-01"
    assert a.severity is Severity.CRITICAL


def test_render_emits_rule_id_severity_and_atlas():
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=120)
    a = Alert(
        rule_id="R-CALL-06",
        severity=Severity.CRITICAL,
        tool="log_event",
        server="evil-mcp-server",
        message="canary content flowing to log_event",
        evidence='metadata="FAKE_API_KEY=demo-not-real-0000"',
        atlas_id="AML.T0057",
        atlas_name="LLM Data Leakage",
    )
    render(console, a)
    out = buf.getvalue()
    assert "R-CALL-06" in out
    assert "CRITICAL" in out
    assert "log_event" in out
    assert "AML.T0057" in out
