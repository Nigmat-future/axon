"""Tests for the env scanner's mapping logic and the discovery orchestrator's
cross-source dedup. Uses synthetic mappings — no real keys, no network.
"""

from axon.models import SourceKind
from axon.scanners import env as env_scanner


def test_scan_mapping_detects_known_and_generic_keys():
    mapping = {
        "OPENAI_API_KEY": "sk-proj-aaa111",
        "DEEPSEEK_API_KEY": "sk-deepseekbbb222",
        "SOMETHING_ELSE": "not-a-key",
        "CUSTOM_API_TOKEN": "tok-generic-ccc333",  # generic catch
        "PATH": "/usr/bin",
    }
    pairs = env_scanner._scan_mapping(mapping, SourceKind.ENV_PROCESS)
    providers = {d.provider_id for d, _ in pairs}
    assert "openai" in providers
    assert "deepseek" in providers
    # Generic _API_TOKEN var is captured (as unknown provider).
    details = {d.source_detail for d, _ in pairs}
    assert "CUSTOM_API_TOKEN" in details
    # Non-key vars are ignored.
    assert "PATH" not in details
    assert "SOMETHING_ELSE" not in details


def test_scan_mapping_pairs_sibling_base_url():
    mapping = {
        "OPENAI_API_KEY": "sk-localkey",
        "OPENAI_BASE_URL": "http://localhost:8080/v1",
    }
    pairs = env_scanner._scan_mapping(mapping, SourceKind.ENV_PROCESS)
    disc = next(d for d, _ in pairs if d.source_detail == "OPENAI_API_KEY")
    assert disc.base_url == "http://localhost:8080/v1"


def test_raw_key_returned_for_validation_but_not_on_discovery():
    mapping = {"ANTHROPIC_API_KEY": "sk-ant-secret999"}
    pairs = env_scanner._scan_mapping(mapping, SourceKind.ENV_PROCESS)
    disc, raw = pairs[0]
    assert raw == "sk-ant-secret999"  # raw key flows in the pipeline tuple
    assert "sk-ant-secret999" not in repr(disc)  # but not on the Discovery
