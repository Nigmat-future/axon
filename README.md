# Axon

**Local-first, capability-aware LLM router gateway.** Axon scans your machine for API keys you've *already* configured, validates them, and stands up a single OpenAI-compatible endpoint that routes each task type (search, backend coding, reasoning, cheap bulk…) to the cost-optimal model — with a dashboard showing which model each role is using.

> Named for the axon — the fiber a neuron uses to route its output signal to the right downstream targets. That's the job: send each request down the right path.

> Like OpenRouter's API fusion, but running on your own machine, configuring itself from the keys already on it.

## Why

Premium models are great but expensive, and you don't need them for search or summarization — a budget model does that at a fraction of the cost. Axon assigns the right model to the right job automatically, and unlike every other gateway, it doesn't make you paste keys: it discovers the ones you already have.

## Status

Early development. **M0 — the discovery engine** is complete: it scans environment variables (process + Windows registry) and a fixed allowlist of config files, detects each key's provider (base_url first, then key prefix, then env var name), and validates with a zero-cost probe — never exposing a key value.

```bash
pip install -e .
axon scan              # discover configured providers (fingerprints only)
axon scan --validate   # also probe which keys authenticate
```

## Architecture

- **Discovery engine** (M0, done) — the wedge. Read-only, consent-gated scan of env vars, the Windows registry, `.env` files, and tool config files (`~/.claude`, `~/.aider.conf.yml`, `~/.continue`, Cursor's `state.vscdb`).
- **Fused endpoint** (M1) — LiteLLM as the provider engine behind an OpenAI-compatible `/v1`.
- **Router** (M2) — static role-based routing for v1. Smart cheap-first cascade is a fast-follow.
- **Dashboard** (M3) — "Active Models" view + discovery cards + cost stats.

## Security

The discovery engine reads secrets, so it is bound by hard rules: read-only, never log/persist/transmit a raw key value (only fingerprints like `..AB12`), outbound calls only to each provider's own endpoint, consent gates before reading files or the OS keychain. See [`SECURITY.md`](SECURITY.md).

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q
```

## License

MIT.
