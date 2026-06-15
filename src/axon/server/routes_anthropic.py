"""Anthropic-compatible ingress: POST /v1/messages.

Accepts the Anthropic Messages request shape and routes it through the egress
layer (LiteLLM translates to the target provider). Supports non-streaming (JSON)
and streaming. Anthropic streaming uses NAMED SSE events
(`event: <type>\\ndata: {json}\\n\\n`), distinct from OpenAI's data-only frames —
so any Anthropic SDK (including Claude Code) works by pointing its base_url here.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from ..registry import resolve_target
from .app import anthropic_error
from .egress import anthropic_messages

router = APIRouter()
logger = logging.getLogger("axon.server")


def _to_dict(obj: Any) -> dict[str, Any]:
    for attr in ("model_dump", "dict", "json"):
        fn = getattr(obj, attr, None)
        if callable(fn):
            out = fn()
            return json.loads(out) if isinstance(out, str) else out
    if isinstance(obj, dict):
        return obj
    return {"value": str(obj)}


async def _sse_stream(response_iter: Any):
    """Yield Anthropic named-event SSE frames from a LiteLLM streaming response.

    Each event carries its `type` as the SSE event name. An event without a
    `type` is skipped rather than guessed — mislabeling it (e.g. as
    message_delta) would corrupt the Anthropic SDK's stream state machine.
    """
    try:
        async for event in response_iter:
            payload = _to_dict(event)
            event_type = payload.get("type")
            if not event_type:
                continue  # don't fabricate a semantic event name
            yield f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"
    except Exception:  # noqa: BLE001 — log server-side, never echo exc to client
        logger.exception("upstream error during Anthropic stream")
        err = {
            "type": "error",
            "error": {"type": "api_error", "message": "upstream provider error"},
        }
        yield f"event: error\ndata: {json.dumps(err)}\n\n"


@router.post("/v1/messages")
async def messages(request: Request):
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        return anthropic_error(400, "request body must be valid JSON")

    model = body.get("model")
    if not model or body.get("messages") is None:
        return anthropic_error(400, "fields 'model' and 'messages' are required")

    vault = request.app.state.vault
    target = resolve_target(model, vault)
    if target is None:
        return anthropic_error(
            404,
            f"no discovered provider can serve model '{model}'. "
            f"Available providers: {vault.providers() or 'none'}.",
            err_type="not_found_error",
        )

    stream = bool(body.get("stream", False))

    try:
        result = await anthropic_messages(target, body=body)
    except Exception:  # noqa: BLE001 — log server-side, never echo exc to client
        logger.exception("upstream error calling provider for model %s", model)
        return anthropic_error(502, "upstream provider error", "api_error")

    if stream:
        return StreamingResponse(
            _sse_stream(result),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
    return JSONResponse(_to_dict(result))
