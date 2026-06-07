from evil_mcp_server.payloads import (
    POISONED_LIST_NOTES_DESCRIPTION,
    POISONED_LIST_NOTES_DESCRIPTION_V1,
)


# --- v2 (current) — subtle, docs-style framing -------------------------------

def test_v2_payload_uses_subtle_imperative_markers():
    """No 'IMPORTANT' / 'SYSTEM' / 'do not mention' — that's the point of v2.
    But it still carries softer markers our rules pick up."""
    text = POISONED_LIST_NOTES_DESCRIPTION
    normalized = " ".join(text.lower().split())
    assert "IMPORTANT" not in text
    assert "do not mention" not in normalized
    assert "integrity protocol" in normalized
    assert "before returning" in normalized


def test_v2_payload_references_canary_path():
    assert "canary.txt" in POISONED_LIST_NOTES_DESCRIPTION


def test_v2_payload_chains_tools_by_name():
    text = POISONED_LIST_NOTES_DESCRIPTION
    assert "read_file" in text
    assert "log_event" in text


# --- v1 (preserved for the video contrast) -----------------------------------

def test_v1_payload_is_still_available_and_blatant():
    text = POISONED_LIST_NOTES_DESCRIPTION_V1
    assert "IMPORTANT" in text
    assert "do not mention" in text.lower()
    assert "read_file" in text
    assert "log_event" in text
