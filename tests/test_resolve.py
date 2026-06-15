"""Tests for provider + endpoint resolution precedence.

The precedence rules (SECURITY.md) are the correctness core of discovery:
base_url FIRST, then DISTINCTIVE key prefix, then env var name, with the
ambiguous bare `sk-` prefix deferring to a specific env var name.
"""

from axon.resolve import resolve


def test_base_url_wins_over_prefix():
    # An Anthropic-prefixed key pointed at OpenRouter resolves to OpenRouter.
    res = resolve(
        api_key="sk-ant-abc123",
        base_url="https://openrouter.ai/api/v1",
        env_var_name="ANTHROPIC_API_KEY",
    )
    assert res.provider_id == "openrouter"
    assert res.detected_via == "base_url"


def test_distinctive_prefix_resolves_anthropic():
    res = resolve(api_key="sk-ant-abc123", base_url=None, env_var_name=None)
    assert res.provider_id == "anthropic"
    assert res.detected_via == "prefix"


def test_openrouter_prefix():
    res = resolve(api_key="sk-or-v1-abc", base_url=None, env_var_name=None)
    assert res.provider_id == "openrouter"


def test_deepseek_env_name_beats_bare_sk_prefix():
    # Regression: DeepSeek keys start with bare `sk-`. The specific env var name
    # MUST win so the key isn't misrouted to OpenAI.
    res = resolve(
        api_key="sk-deepseek-style-key",
        base_url=None,
        env_var_name="DEEPSEEK_API_KEY",
    )
    assert res.provider_id == "deepseek"
    assert res.detected_via == "env-name"


def test_openai_proj_prefix_still_wins_over_env_name():
    # `sk-proj-` is distinctive (not ambiguous), so it resolves to OpenAI by
    # prefix even though OPENAI_API_KEY env name would also work.
    res = resolve(
        api_key="sk-proj-abc",
        base_url=None,
        env_var_name="OPENAI_API_KEY",
    )
    assert res.provider_id == "openai"
    assert res.detected_via == "prefix"


def test_bare_sk_with_no_env_name_falls_back_to_openai():
    # No env name to defer to: even the weak `sk-` prefix is better than nothing.
    res = resolve(api_key="sk-plainkey123", base_url=None, env_var_name=None)
    assert res.provider_id == "openai"


def test_unknown_custom_base_url_keeps_endpoint():
    # A self-hosted OpenAI-compatible proxy: unknown provider but base_url kept.
    res = resolve(
        api_key="sk-localproxykey",
        base_url="http://localhost:11434/v1",
        env_var_name=None,
    )
    # bare sk- with no env name falls back to openai by prefix, but base_url
    # is preserved as given.
    assert res.base_url == "http://localhost:11434/v1"


def test_groq_distinctive_prefix():
    res = resolve(api_key="gsk_abc123", base_url=None, env_var_name="GROQ_API_KEY")
    assert res.provider_id == "groq"
