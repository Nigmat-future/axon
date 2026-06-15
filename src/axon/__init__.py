"""Axon — local-first, capability-aware LLM router gateway.

The M0 surface is the discovery engine: scan the machine for already-configured
API keys, detect their provider, and validate them — without ever exposing a key
value. See SECURITY.md for the hard rules this package enforces.
"""

__version__ = "0.0.1"
