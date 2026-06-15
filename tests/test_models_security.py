"""Tests for the security invariants of the discovery models.

The non-negotiable property (SECURITY.md rule 2): a Discovery never holds the
raw key, only a fingerprint. These tests assert that property structurally.
"""

import dataclasses

from axon.models import Discovery, KeyFingerprint, SourceKind


SECRET = "sk-ant-supersecret-value-1234567890ABCD"


def test_fingerprint_is_not_reversible_and_hides_value():
    fp = KeyFingerprint.of(SECRET)
    assert fp.last4 == "ABCD"
    assert fp.length == len(SECRET)
    # The fingerprint string never contains the full secret.
    assert SECRET not in fp.display()
    assert fp.sha256_prefix in fp.display()


def test_fingerprint_stable_and_distinct():
    assert KeyFingerprint.of(SECRET) == KeyFingerprint.of(SECRET)
    assert KeyFingerprint.of(SECRET) != KeyFingerprint.of(SECRET + "x")


def test_discovery_has_no_field_holding_raw_key():
    d = Discovery.capture(
        api_key=SECRET,
        provider_id="anthropic",
        source=SourceKind.ENV_PROCESS,
        source_detail="ANTHROPIC_API_KEY",
    )
    # No field on the Discovery may equal the raw secret.
    for field in dataclasses.fields(d):
        assert getattr(d, field.name) != SECRET
    # And the secret must not appear anywhere in its repr.
    assert SECRET not in repr(d)


def test_short_key_does_not_leak_via_last4():
    fp = KeyFingerprint.of("ab")
    assert "ab" not in fp.last4  # masked when shorter than 4 chars
    assert fp.last4 == "??"


def test_dedup_key_groups_same_provider_and_key():
    d1 = Discovery.capture(
        api_key=SECRET, provider_id="anthropic",
        source=SourceKind.ENV_PROCESS, source_detail="ANTHROPIC_API_KEY",
    )
    d2 = Discovery.capture(
        api_key=SECRET, provider_id="anthropic",
        source=SourceKind.DOTENV, source_detail="/home/x/.env",
    )
    assert d1.dedup_key == d2.dedup_key
