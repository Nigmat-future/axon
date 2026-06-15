"""Security regression tests for the egress layer.

These cover the P0/P1 findings from the M1 adversarial review: a client request
body must never be able to override the vault-resolved credential or endpoint,
because doing so would redirect the operator's real provider key to a
client-chosen URL (key exfiltration / SSRF). No network, no LiteLLM call — these
test the request-shaping primitives directly.
"""

from axon.registry import LiteLLMTarget
from axon.server.egress import FORBIDDEN_CLIENT_FIELDS, _apply_target, strip_forbidden


def test_strip_forbidden_removes_egress_control_fields():
    hostile = {
        "temperature": 0.5,            # legitimate, kept
        "max_tokens": 100,             # legitimate, kept
        "api_key": "sk-attacker",      # must be dropped
        "api_base": "https://evil.example/v1",  # must be dropped
        "base_url": "https://evil.example",     # must be dropped
        "custom_llm_provider": "openai",         # must be dropped
        "extra_headers": {"x": "y"},   # must be dropped
        "organization": "org-evil",    # must be dropped
    }
    clean = strip_forbidden(hostile)
    assert clean == {"temperature": 0.5, "max_tokens": 100}
    for f in FORBIDDEN_CLIENT_FIELDS:
        assert f not in clean


def test_apply_target_overrides_client_supplied_endpoint():
    # Even if a forbidden field somehow survived, _apply_target must win.
    target = LiteLLMTarget(
        litellm_model="openai/gpt-4o",
        api_key="sk-real-vault-key",
        api_base="https://api.openai.com/v1",
        provider_id="openai",
    )
    kwargs = {"api_base": "https://evil.example", "api_key": "sk-attacker"}
    _apply_target(kwargs, target)
    assert kwargs["api_key"] == "sk-real-vault-key"      # trusted key wins
    assert kwargs["api_base"] == "https://api.openai.com/v1"  # trusted base wins
    assert kwargs["model"] == "openai/gpt-4o"


def test_apply_target_clears_api_base_when_resolved_is_none():
    # P1: a credential with base_url=None must NOT inherit a client api_base.
    target = LiteLLMTarget(
        litellm_model="anthropic/claude-x",
        api_key="sk-real",
        api_base=None,
        provider_id="anthropic",
    )
    kwargs = {"api_base": "https://evil.example"}
    _apply_target(kwargs, target)
    assert "api_base" not in kwargs  # cleared, not left as the client's value
    assert kwargs["api_key"] == "sk-real"


def test_litellm_target_repr_hides_key():
    target = LiteLLMTarget(
        litellm_model="openai/gpt-4o",
        api_key="sk-super-secret-value",
        api_base=None,
        provider_id="openai",
    )
    assert "sk-super-secret-value" not in repr(target)


def test_vault_records_shadowed_duplicate_instead_of_dropping():
    from axon.models import Discovery, SourceKind
    from axon.registry import ProviderCredential, SecretVault

    def cred(src: SourceKind, key: str) -> ProviderCredential:
        disc = Discovery.capture(
            api_key=key, provider_id="openai", source=src,
            source_detail="OPENAI_API_KEY",
        )
        return ProviderCredential(
            provider_id="openai", api_key=key, base_url=None, discovery=disc
        )

    v = SecretVault()
    v.add(cred(SourceKind.ENV_PROCESS, "sk-env-key"))   # first wins
    v.add(cred(SourceKind.CONFIG_FILE, "sk-config-key"))  # shadowed, not lost

    assert len(v) == 1
    assert v.get("openai").api_key == "sk-env-key"
    assert len(v.shadowed) == 1
    assert v.shadowed[0].discovery.source == SourceKind.CONFIG_FILE
