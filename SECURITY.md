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

## Two paths: discovery vs serving

Axon has two operating paths with deliberately different secret models. The hard rules above govern the **discovery path** (`axon scan`), which only ever needs fingerprints.

The **serving path** (`axon serve`) is a long-running gateway, and a gateway must hold raw keys in memory to forward requests — this is intrinsic to being a proxy (LiteLLM proxy, Bifrost, and every other gateway do the same). The serving path is bound by its own rules:

- **Keys live only in the process, only in memory.** They are loaded into an in-memory `SecretVault`, never written to disk, never logged. The vault's `__repr__` is redacted to fingerprints, and the credential-carrying `ProviderCredential` and `LiteLLMTarget` objects set `repr=False` on their key field, so an accidental log or traceback frame leaks nothing.
- **Client request bodies are untrusted and cannot steer egress.** A caller cannot override which endpoint or credential a request uses: egress-control fields (`api_key`, `api_base`, `base_url`, `custom_llm_provider`, `extra_headers`, …) are stripped from inbound request bodies, and the vault-resolved `(model, api_key, api_base)` are applied last so they always win. `api_base` is set to exactly the resolved value or removed — never inherited from client input. Without this, a body field like `{"api_base": "https://attacker/v1"}` would redirect your real provider key to an attacker-chosen URL.
- **Outbound only to the resolved provider endpoint.** Egress goes through LiteLLM to the discovered `base_url` (honoring a custom/proxy endpoint) and nowhere else. Because a discovered `base_url` may have come from an untrusted config file, `axon serve` prints each credential's resolved endpoint at startup and warns when it is a non-default or `http://` (cleartext) endpoint — so a poisoned `base_url` is visible, not silent.
- **Errors never echo upstream exception text.** Provider/LiteLLM exceptions can embed the api_key or api_base; the gateway logs them server-side and returns only a generic `"upstream provider error"` to the client (both JSON and SSE error frames).
- **Localhost by default.** `axon serve` binds `127.0.0.1`. Binding any non-localhost address is **refused** unless `AXON_API_KEY` is set, because an open bind would let anyone on the network spend your keys.
- **Optional inbound gate.** When `AXON_API_KEY` is set, every inbound request must present it (`Authorization: Bearer …` or `x-api-key: …`), compared in constant time (`hmac.compare_digest`); otherwise the gate is off (safe only because the bind is localhost). `/healthz` is unauthenticated and reports only liveness, not which providers are loaded.
- **The serving path never re-exposes keys downstream.** Discovered keys are used to authenticate to providers; they are not echoed in `/v1/models`, responses, or errors.


## Provider detection order

Provider is resolved **base_url first, key prefix second, env var name last**, because aggregators (OpenRouter, DeepSeek, local proxies) reuse OpenAI-style `sk-` prefixes. A custom base_url is the strongest signal that a key targets an aggregator rather than the first-party API.

## Validation semantics

A `200` from `GET {base_url}/v1/models` means **the key authenticates** — it does **not** prove the account has credit or quota. The UI reports "authenticates", never "working".

## Dependencies

The M0 discovery engine depends only on the standard library plus `httpx`, `pyyaml`, `rich`, and `typer`. Dependencies are pinned. A key-aggregating tool must minimize its dependency surface (cf. the LiteLLM PyPI supply-chain incident).
