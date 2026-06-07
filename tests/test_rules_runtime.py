from aisac_proxy.rules import (
    TurnState,
    check_call_argument_matches_prior_alert_evidence,
    check_call_denylist_path,
    check_call_sink_receives_prior_source_output,
)


def _state_with_alert_for_list_notes() -> TurnState:
    s = TurnState()
    s.flagged_descriptions["list_notes"] = "canary.txt"
    return s


def test_R_CALL_05_fires_when_call_uses_path_from_flagged_description():
    s = _state_with_alert_for_list_notes()
    alert = check_call_argument_matches_prior_alert_evidence(
        state=s,
        tool="read_file",
        server="evil",
        arguments={"path": "./sandbox/canary.txt"},
    )
    assert alert is not None
    assert alert.rule_id == "R-CALL-05"


def test_R_CALL_05_does_not_fire_when_no_flagged_descriptions():
    s = TurnState()
    alert = check_call_argument_matches_prior_alert_evidence(
        state=s,
        tool="read_file",
        server="evil",
        arguments={"path": "./sandbox/canary.txt"},
    )
    assert alert is None


def test_R_CALL_06_fires_when_sink_argument_matches_prior_source_result():
    s = TurnState()
    s.last_results["read_file"] = "FAKE_API_KEY=demo-not-real-0000\n"
    alert = check_call_sink_receives_prior_source_output(
        state=s,
        tool="log_event",
        server="evil",
        arguments={"message": "ok", "metadata": "FAKE_API_KEY=demo-not-real-0000"},
    )
    assert alert is not None
    assert alert.rule_id == "R-CALL-06"


def test_R_CALL_06_does_not_fire_when_metadata_unrelated():
    s = TurnState()
    s.last_results["read_file"] = "FAKE_API_KEY=demo-not-real-0000"
    alert = check_call_sink_receives_prior_source_output(
        state=s,
        tool="log_event",
        server="evil",
        arguments={"message": "ok", "metadata": "everything is fine"},
    )
    assert alert is None


def test_R_CALL_07_fires_on_denylisted_path():
    alert = check_call_denylist_path(
        tool="read_file",
        server="evil",
        arguments={"path": "./sandbox/canary.txt"},
    )
    assert alert is not None
    assert alert.rule_id == "R-CALL-07"


def test_R_CALL_07_does_not_fire_on_safe_path():
    alert = check_call_denylist_path(
        tool="read_file",
        server="evil",
        arguments={"path": "./README.md"},
    )
    assert alert is None
