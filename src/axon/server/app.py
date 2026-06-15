"""FastAPI app factory: wires the vault, inbound auth, and the two ingresses.

The app holds a `SecretVault` in `app.state.vault`. Inbound auth is optional and
controlled by `AXON_API_KEY`: when set, every request must present it
(Bearer or x-api-key). When binding to a non-localhost address, the serve CLI
REQUIRES it (see cli/serve) — a key-holding endpoint must not be open.
"""

from __future__ import annotations

import hmac
import os
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from .. import __version__
from ..registry import SecretVault


def _check_inbound_auth(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> None:
    """Enforce the inbound gateway key when AXON_API_KEY is set.

    Accepts either `Authorization: Bearer <key>` (OpenAI style) or
    `x-api-key: <key>` (Anthropic style). No-op when AXON_API_KEY is unset.
    Uses a constant-time comparison so the key can't be recovered by timing.
    """
    expected = os.environ.get("AXON_API_KEY")
    if not expected:
        return
    presented: str | None = None
    if authorization and authorization.lower().startswith("bearer "):
        presented = authorization[7:].strip()
    elif x_api_key:
        presented = x_api_key.strip()
    if not presented or not hmac.compare_digest(
        presented.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(status_code=401, detail="invalid or missing Axon API key")


def create_app(vault: SecretVault | None = None) -> FastAPI:
    """Build the Axon serving app. `vault` is injected for tests; in production
    the serve CLI builds it from discovery and passes it here.
    """
    app = FastAPI(title="Axon", version=__version__)
    app.state.vault = vault if vault is not None else SecretVault()

    auth = Depends(_check_inbound_auth)

    # Routers are imported here (not at module top) so importing the app factory
    # doesn't pull in litellm until the server is actually constructed.
    from .routes_openai import router as openai_router
    from .routes_anthropic import router as anthropic_router

    app.include_router(openai_router, dependencies=[auth])
    app.include_router(anthropic_router, dependencies=[auth])

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        # Unauthenticated: report liveness only, not which credentials are loaded
        # (avoid leaking provider inventory to an unauthenticated network client).
        return {"status": "ok", "version": __version__}

    return app


def openai_error(status: int, message: str, err_type: str = "invalid_request_error"):
    """An OpenAI-shaped error response."""
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "message": message,
                "type": err_type,
                "param": None,
                "code": None,
            }
        },
    )


def anthropic_error(status: int, message: str, err_type: str = "invalid_request_error"):
    """An Anthropic-shaped error response."""
    return JSONResponse(
        status_code=status,
        content={"type": "error", "error": {"type": err_type, "message": message}},
    )
