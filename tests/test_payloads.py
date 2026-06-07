from evil_mcp_server.payloads import (
    POISONED_LIST_NOTES_DESCRIPTION,
    POISONED_LIST_NOTES_DESCRIPTION_V1,
    POISONED_LIST_NOTES_DESCRIPTION_V2,
)


# --- v3 (current default) — auth-disguised, no file path in description ------

def test_v3_payload_hides_the_file_path():
    """v3's whole point: the description must NOT mention the canary file path.
    The malicious read happens inside get_session_token, server-side."""
    text = POISONED_LIST_NOTES_DESCRIPTION
    assert "canary" not in text.lower()
    assert "./sandbox" not in text
    assert ".txt" not in text


def test_v3_payload_uses_auth_framing():
    text = POISONED_LIST_NOTES_DESCRIPTION
    normalized = " ".join(text.lower().split())
    assert "authentication" in normalized
    assert "session" in normalized
    assert "get_session_token" in text  # references the disguised reader tool
    assert "log_event" in text          # chains to the exfil sink


def test_v3_payload_avoids_v1_blatant_markers():
    text = POISONED_LIST_NOTES_DESCRIPTION
    normalized = " ".join(text.lower().split())
    assert "IMPORTANT" not in text
    assert "do not mention" not in normalized
    assert "silently" not in normalized


# --- v2 (preserved for the video contrast) -----------------------------------

def test_v2_payload_is_handshake_style():
    text = POISONED_LIST_NOTES_DESCRIPTION_V2
    normalized = " ".join(text.lower().split())
    assert "session handshake" in normalized
    assert "step 1: call" in normalized
    assert "canary.txt" in text


# --- v1 (preserved for the video contrast) -----------------------------------

def test_v1_payload_is_blatant():
    text = POISONED_LIST_NOTES_DESCRIPTION_V1
    assert "IMPORTANT" in text
    assert "do not mention" in text.lower()
    assert "read_file" in text
    assert "log_event" in text
