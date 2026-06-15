"""OpenAI-compatible ingress: POST /v1/chat/completions, GET /v1/models.

Routes a requested model to a discovered provider via the egress layer. Both
non-streaming (JSON) and streaming (SSE, `data: {chunk}\\n\\n` … `data: [DONE]`)
are supported, matching the OpenAI client contract so any OpenAI SDK works by
pointing base_url at Axon.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from ..registry import advertised_models, resolve_target
from .app import openai_error
from .egress import openai_completion

router = APIRouter()
logger = logging.getLogger("axon.server")

# OpenAI request fields handled explicitly; everything else is passed through.
_RESERVED = {"model", "messages", "stream"}


def _to_dict(obj: Any) -> dict[str, Any]:
    """Best-effort conversion of a LiteLLM ModelResponse to a plain dict."""
    for attr in ("model_dump", "dict", "json"):
        fn = getattr(obj, attr, None)
        if callable(fn):
            out = fn()
            return json.loads(out) if isinstance(out, str) else out
    if isinstance(obj, dict):
        return obj
    return {"data": str(obj)}


@router.get("/v1/models")
async def list_models(request: Request) -> JSONResponse:
    """Advertise concrete, routable model ids for the discovered providers."""
    vault = request.app.state.vault
    data = [
        {"id": mid, "object": "model", "owned_by": "axon", "created": 0}
        for mid in advertised_models(vault)
    ]
    return JSONResponse({"object": "list", "data": data})


async def _sse_stream(response_iter: Any):
    """Yield OpenAI SSE frames from a LiteLLM streaming response."""
    try:
        async for chunk in response_iter:
            payload = _to_dict(chunk)
            yield f"data: {json.dumps(payload)}\n\n"
    except Exception:  # noqa: BLE001 — log server-side, never echo exc to client
        logger.exception("upstream error during OpenAI stream")
        err = {
            "error": {
                "message": "upstream provider error",
                "type": "upstream_error",
                "param": None,
                "code": None,
            }
        }
        yield f"data: {json.dumps(err)}\n\n"
    yield "data: [DONE]\n\n"


@router.post("/v1/chat/completions")
async def chat_completions(request: Request):
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        return openai_error(400, "request body must be valid JSON")

    model = body.get("model")
    messages = body.get("messages")
    if not model or messages is None:
        return openai_error(400, "fields 'model' and 'messages' are required")

    vault = request.app.state.vault
    target = resolve_target(model, vault)
    if target is None:
        return openai_error(
            404,
            f"no discovered provider can serve model '{model}'. "
            f"Available providers: {vault.providers() or 'none'}.",
            err_type="model_not_found",
        )

    stream = bool(body.get("stream", False))
    params = {k: v for k, v in body.items() if k not in _RESERVED}

    try:
        result = await openai_completion(
            target, messages=messages, stream=stream, params=params
        )
    except Exception:  # noqa: BLE001 — log server-side, never echo exc to client
        logger.exception("upstream error calling provider for model %s", model)
        return openai_error(502, "upstream provider error", "upstream_error")

    if stream:
        return StreamingResponse(
            _sse_stream(result),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
    return JSONResponse(_to_dict(result))
