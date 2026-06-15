"""Tests for Stage 2 config-file key detection: field-name matching (the
Claude Code `env` block case) and value-shape matching, with sibling base_url
pairing. No real keys; constructs parsed structures directly.
"""

from pathlib import Path

from axon.scanners.config_files import _walk_json_for_keys


def test_field_name_detection_with_sibling_base_url():
    # Mirrors Claude Code settings.json: an env block with an auth token + base.
    data = {
        "model": "claude-opus-4-8",
        "env": {
            "ANTHROPIC_AUTH_TOKEN": "tok-realsecret-AGED",
            "ANTHROPIC_BASE_URL": "http://127.0.0.1:4000",
        },
    }
    pairs = _walk_json_for_keys(data, Path("settings.json"), note_apikeyhelper=True)
    keys = [(d, raw) for d, raw in pairs if d.fingerprint.length > 0]
    assert len(keys) == 1
    disc, raw = keys[0]
    assert disc.provider_id == "anthropic"
    assert disc.base_url == "http://127.0.0.1:4000"  # sibling paired in
    assert "ANTHROPIC_AUTH_TOKEN" in disc.source_detail
    assert raw == "tok-realsecret-AGED"
    assert "tok-realsecret-AGED" not in repr(disc)  # never on the Discovery


def test_value_shape_detection_for_unknown_field():
    # A key stored under a non-obvious field name is caught by value shape.
    data = {"providers": [{"token": "sk-ant-shapedsecret1234567890"}]}
    pairs = _walk_json_for_keys(data, Path("x.json"), note_apikeyhelper=False)
    keys = [(d, raw) for d, raw in pairs if d.fingerprint.length > 0]
    assert any(d.provider_id == "anthropic" for d, _ in keys)


def test_apikeyhelper_noted_not_executed():
    data = {"apiKeyHelper": "/bin/echo should-never-run"}
    pairs = _walk_json_for_keys(data, Path("settings.json"), note_apikeyhelper=True)
    markers = [d for d, _ in pairs if d.fingerprint.length == 0]
    assert len(markers) == 1
    assert "not executed" in markers[0].notes[0]
    # The helper command must not be captured as a key.
    assert all("/bin/echo" not in repr(d) for d, _ in pairs)


def test_oauth_tokens_not_misdetected_as_keys():
    # .credentials.json shape: OAuth fields must NOT be surfaced as API keys.
    data = {
        "claudeAiOauth": {
            "accessToken": "oauth-access-abc",
            "refreshToken": "oauth-refresh-def",
            "subscriptionType": "max",
        }
    }
    pairs = _walk_json_for_keys(data, Path(".credentials.json"), note_apikeyhelper=False)
    keys = [d for d, raw in pairs if d.fingerprint.length > 0]
    assert keys == []  # accessToken/refreshToken aren't _API_KEY/_API_TOKEN names
