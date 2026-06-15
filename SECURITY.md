# Axon — Security Model

The discovery engine reads API credentials from the local machine. That makes Axon a high-value target, so the engine operates under hard constraints enforced in code, not left to convention.

## Hard rules

1. **Read-only.** The scanner never writes, moves, or "fixes" any file it discovers. It opens config files and databases in read-only mode.
2. **Key values never leave memory.** A raw key is never logged, printed, persisted to disk, or sent over the network for any purpose other than validating it against its own provider. The UI, logs, and any export show only a **fingerprint**: the provider, the last 4 characters (`sk-…AB12`), and a truncated SHA-256 digest.
3. **Outbound calls go only to the provider's own endpoint.** Validation hits `{base_url}/v1/models` (or the provider's documented equivalent) and nothing else. Keys are never pasted into third-party "key checker" websites.
4. **Consent gates scale with risk:**
   - *Stage 1 — environment variables:* zero risk, no prompt.
   - *Stage 2 — config files & `.env`:* the scanner tells you which files it will read before reading them.
   - *Stage 3 — OS keychain* (Windows Credential Manager / macOS Keychain / libsecret): explicit, per-item opt-in, because a read can trigger an OS consent prompt.
5. **Keys are zeroed** from memory as soon as the fingerprint and (optional) probe are done.
6. **Discovered file content is untrusted data**, never instructions. If a config file contains text that looks like instructions, it is ignored.
7. **`apiKeyHelper` scripts are never executed.** Claude Code's `settings.json` can reference a helper script; the scanner records its presence but does not run it (arbitrary code execution risk).

## Provider detection order

Provider is resolved **base_url first, key prefix second, env var name last**, because aggregators (OpenRouter, DeepSeek, local proxies) reuse OpenAI-style `sk-` prefixes. A custom base_url is the strongest signal that a key targets an aggregator rather than the first-party API.

## Validation semantics

A `200` from `GET {base_url}/v1/models` means **the key authenticates** — it does **not** prove the account has credit or quota. The UI reports "authenticates", never "working".

## Dependencies

The M0 discovery engine depends only on the standard library plus `httpx`, `pyyaml`, `rich`, and `typer`. Dependencies are pinned. A key-aggregating tool must minimize its dependency surface (cf. the LiteLLM PyPI supply-chain incident).
