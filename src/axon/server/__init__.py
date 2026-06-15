"""Axon serving layer (M1): a local dual-ingress LLM gateway.

Exposes two compatible entry points over the providers Axon discovered:
  * OpenAI-compatible   — POST /v1/chat/completions, GET /v1/models
  * Anthropic-compatible — POST /v1/messages

Both stream (SSE) and route egress through LiteLLM. See SECURITY.md for the
serving-path secret model (raw keys held in memory, localhost bind by default).
"""
