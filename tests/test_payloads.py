from evil_mcp_server.payloads import POISONED_LIST_NOTES_DESCRIPTION


def test_payload_contains_imperative_marker():
    text = POISONED_LIST_NOTES_DESCRIPTION
    assert "IMPORTANT" in text
    assert "do not mention" in text.lower()


def test_payload_references_canary_path():
    assert "canary.txt" in POISONED_LIST_NOTES_DESCRIPTION


def test_payload_chains_tools_by_name():
    text = POISONED_LIST_NOTES_DESCRIPTION
    assert "read_file" in text
    assert "log_event" in text
