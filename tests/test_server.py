"""Tests for the M1 dual-ingress server, with the LiteLLM egress mocked out so
no network or real keys are involved. Verifies routing, streaming shape, error
mapping, the /v1/models advertisement, and inbound auth.
"""

import json

import pytest
from fastapi.testclient import TestClient

from axon.models import Discovery, SourceKind
from axon.registry import ProviderCredential, SecretVault
from axon.server import app as app_module
from axon.server import routes_anthropic, routes_openai


def _vault_with(*provider_ids: str) -> SecretVault:
    v = SecretVault()
    for pid in provider_ids:
        disc = Discovery.capture(
            api_key=f"sk-fake-{pid}-key",
            provider_id=pid,
            source=SourceKind.ENV_PROCESS,
            source_detail=f"{pid.upper()}_API_KEY",
        )
        v.add(
            ProviderCredential(
                provider_id=pid,
                api_key=f"sk-fake-{pid}-key",
                base_url=None,
                discovery=disc,
            )
        )
    return v


@pytest.fixture
def client():
    app = app_module.create_app(vault=_vault_with("openai", "anthropic"))
    return TestClient(app)


# --- /v1/models + health ---------------------------------------------------

def test_models_lists_routable_model_ids(client):
    r = client.get("/v1/models")
    assert r.status_code == 200
    ids = {row["id"] for row in r.json()["data"]}
    # Concrete, routable ids — not bare provider ids.
    assert "gpt-4o" in ids
    assert "claude-sonnet-4-6" in ids
    assert "openai" not in ids  # bare provider id would 404 if sent back
    # Every advertised id must actually classify to a served provider.
    from axon.registry import classify_model

    assert all(classify_model(i) in {"openai", "anthropic"} for i in ids)


def test_healthz_does_not_leak_provider_inventory(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    # Unauthenticated health must not enumerate loaded providers.
    assert "providers" not in r.json()


# --- OpenAI ingress --------------------------------------------------------

def test_openai_chat_completion_non_streaming(client, monkeypatch):
    captured = {}

    async def fake_completion(target, *, messages, stream, params):
        captured["model"] = target.litellm_model
        captured["api_key"] = target.api_key
        captured["stream"] = stream
        return {"id": "x", "object": "chat.completion", "choices": []}

    monkeypatch.setattr(routes_openai, "openai_completion", fake_completion)

    r = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert r.status_code == 200
    assert r.json()["object"] == "chat.completion"
    # gpt-4o classified to openai, prefixed for litellm, real key from vault.
    assert captured["model"] == "openai/gpt-4o"
    assert captured["api_key"] == "sk-fake-openai-key"
    assert captured["stream"] is False


def test_openai_unknown_model_404(client):
    r = client.post(
        "/v1/chat/completions",
        json={"model": "mystery-model", "messages": []},
    )
    assert r.status_code == 404
    assert r.json()["error"]["type"] == "model_not_found"


def test_openai_missing_fields_400(client):
    r = client.post("/v1/chat/completions", json={"model": "gpt-4o"})
    assert r.status_code == 400


def test_openai_streaming_sse(client, monkeypatch):
    async def fake_completion(target, *, messages, stream, params):
        async def gen():
            yield {"id": "1", "choices": [{"delta": {"content": "he"}}]}
            yield {"id": "1", "choices": [{"delta": {"content": "llo"}}]}
        return gen()

    monkeypatch.setattr(routes_openai, "openai_completion", fake_completion)

    r = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o", "messages": [], "stream": True},
    )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    body = r.text
    assert "data: " in body
    assert body.strip().endswith("data: [DONE]")
    # two content frames present
    assert body.count("data: ") == 3  # 2 chunks + [DONE]


def test_openai_upstream_error_maps_502(client, monkeypatch):
    async def boom(target, *, messages, stream, params):
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(routes_openai, "openai_completion", boom)
    r = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o", "messages": []},
    )
    assert r.status_code == 502
    assert r.json()["error"]["type"] == "upstream_error"


# --- Anthropic ingress -----------------------------------------------------

def test_anthropic_messages_non_streaming(client, monkeypatch):
    captured = {}

    async def fake_messages(target, *, body):
        captured["model"] = target.litellm_model
        captured["api_key"] = target.api_key
        return {"type": "message", "role": "assistant", "content": []}

    monkeypatch.setattr(routes_anthropic, "anthropic_messages", fake_messages)

    r = client.post(
        "/v1/messages",
        json={
            "model": "claude-sonnet-4-6",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 64,
        },
    )
    assert r.status_code == 200
    assert r.json()["type"] == "message"
    assert captured["model"] == "anthropic/claude-sonnet-4-6"
    assert captured["api_key"] == "sk-fake-anthropic-key"


def test_anthropic_streaming_named_events(client, monkeypatch):
    async def fake_messages(target, *, body):
        async def gen():
            yield {"type": "message_start", "message": {"id": "m"}}
            yield {"type": "content_block_delta", "delta": {"text": "hi"}}
            yield {"type": "message_stop"}
        return gen()

    monkeypatch.setattr(routes_anthropic, "anthropic_messages", fake_messages)

    r = client.post(
        "/v1/messages",
        json={"model": "claude-sonnet-4-6", "messages": [], "stream": True},
    )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    body = r.text
    # Anthropic uses named events.
    assert "event: message_start" in body
    assert "event: content_block_delta" in body
    assert "event: message_stop" in body


def test_anthropic_unknown_model_404(client):
    r = client.post(
        "/v1/messages",
        json={"model": "mystery", "messages": [], "max_tokens": 16},
    )
    assert r.status_code == 404
    assert r.json()["type"] == "error"
    assert r.json()["error"]["type"] == "not_found_error"


# --- inbound auth ----------------------------------------------------------

def test_inbound_auth_enforced_when_key_set(monkeypatch):
    monkeypatch.setenv("AXON_API_KEY", "secret-gate")
    app = app_module.create_app(vault=_vault_with("openai"))
    c = TestClient(app)

    # No credentials -> 401
    r = c.get("/v1/models")
    assert r.status_code == 401

    # Correct Bearer -> ok
    r = c.get("/v1/models", headers={"Authorization": "Bearer secret-gate"})
    assert r.status_code == 200

    # Correct x-api-key -> ok
    r = c.get("/v1/models", headers={"x-api-key": "secret-gate"})
    assert r.status_code == 200

    # Wrong key -> 401
    r = c.get("/v1/models", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_no_auth_required_when_key_unset(monkeypatch):
    monkeypatch.delenv("AXON_API_KEY", raising=False)
    app = app_module.create_app(vault=_vault_with("openai"))
    c = TestClient(app)
    assert c.get("/v1/models").status_code == 200


# --- error responses never echo upstream exception text --------------------

def test_openai_error_does_not_leak_exception_detail(client, monkeypatch):
    # The upstream exception text contains a key — it must NOT reach the client.
    async def boom(target, *, messages, stream, params):
        raise RuntimeError("401 from https://api.openai.com key=sk-LEAKED-SECRET")

    monkeypatch.setattr(routes_openai, "openai_completion", boom)
    r = client.post("/v1/chat/completions", json={"model": "gpt-4o", "messages": []})
    assert r.status_code == 502
    assert "sk-LEAKED-SECRET" not in r.text
    assert r.json()["error"]["message"] == "upstream provider error"


def test_anthropic_error_does_not_leak_exception_detail(client, monkeypatch):
    async def boom(target, *, body):
        raise RuntimeError("connection to https://proxy key=sk-ant-LEAKED failed")

    monkeypatch.setattr(routes_anthropic, "anthropic_messages", boom)
    r = client.post(
        "/v1/messages",
        json={"model": "claude-sonnet-4-6", "messages": [], "max_tokens": 8},
    )
    assert r.status_code == 502
    assert "sk-ant-LEAKED" not in r.text


def test_provider_credential_repr_hides_key():
    disc = Discovery.capture(
        api_key="sk-secret-cred-value",
        provider_id="openai",
        source=SourceKind.ENV_PROCESS,
        source_detail="OPENAI_API_KEY",
    )
    cred = ProviderCredential(
        provider_id="openai",
        api_key="sk-secret-cred-value",
        base_url=None,
        discovery=disc,
    )
    assert "sk-secret-cred-value" not in repr(cred)
