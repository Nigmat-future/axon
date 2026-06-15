"""Egress: the thin layer that calls providers via LiteLLM.

Two primitives, mirroring the two ingresses:
  * `openai_completion` -> litellm.acompletion (OpenAI chat-completions shape)
  * `anthropic_messages` -> litellm.anthropic.messages.acreate (Messages shape)

SECURITY: client request bodies are UNTRUSTED. They must never override the
credential or endpoint resolved from the vault. Egress-control fields
(api_key, api_base, base_url, custom_llm_provider, …) are stripped from client
input, and the trusted (model, api_key, api_base) are assigned AFTER the
client params so they always win. api_base is set to exactly the resolved
value or removed entirely — never left to a client-supplied value.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..registry import LiteLLMTarget

# Fields a client must never be able to set — they steer which endpoint the
# request (carrying the operator's real key) is sent to, or which credential is
# used. Stripped from all client input before egress.
FORBIDDEN_CLIENT_FIELDS: frozenset[str] = frozenset(
    {
        "api_key",
        "api_base",
        "base_url",
        "api_version",
        "custom_llm_provider",
        "api_type",
        "organization",
        "azure_ad_token",
        "aws_access_key_id",
        "aws_secret_access_key",
        "vertex_credentials",
        "extra_headers",
        "headers",
    }
)


def strip_forbidden(params: dict[str, Any]) -> dict[str, Any]:
    """Drop egress-control fields from untrusted client params."""
    return {k: v for k, v in params.items() if k not in FORBIDDEN_CLIENT_FIELDS}


def _litellm():
    import litellm

    litellm.drop_params = True  # tolerate provider-specific param mismatches
    return litellm


def _apply_target(kwargs: dict[str, Any], target: "LiteLLMTarget") -> dict[str, Any]:
    """Assign trusted credential/endpoint LAST so client input can't override.

    api_base is set to exactly the resolved value, or removed — never inherited
    from client input.
    """
    kwargs["model"] = target.litellm_model
    kwargs["api_key"] = target.api_key
    if target.api_base:
        kwargs["api_base"] = target.api_base
    else:
        kwargs.pop("api_base", None)
    return kwargs


async def openai_completion(
    target: "LiteLLMTarget",
    *,
    messages: list[dict[str, Any]],
    stream: bool,
    params: dict[str, Any],
) -> Any:
    """Call a provider with OpenAI chat-completions input via LiteLLM.

    `params` is untrusted client input; forbidden egress-control fields are
    stripped and the trusted target is applied last.
    """
    litellm = _litellm()
    kwargs: dict[str, Any] = dict(strip_forbidden(params))
    kwargs["messages"] = messages
    kwargs["stream"] = stream
    _apply_target(kwargs, target)
    return await litellm.acompletion(**kwargs)


async def anthropic_messages(
    target: "LiteLLMTarget",
    *,
    body: dict[str, Any],
) -> Any:
    """Call a provider with Anthropic Messages input via LiteLLM.

    `body` is the untrusted parsed /v1/messages request; forbidden egress-control
    fields are stripped and the trusted target is applied last. max_tokens is
    required by the Messages API, so a default is injected when absent.
    """
    litellm = _litellm()
    call: dict[str, Any] = dict(strip_forbidden(body))
    call.setdefault("max_tokens", 1024)
    _apply_target(call, target)
    return await litellm.anthropic.messages.acreate(**call)
