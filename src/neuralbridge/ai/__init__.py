"""NeuralBridge AI — the /ai control-plane slice.

This package is the agent orchestration layer for the ``/ai`` surface:
session/actor identity, a minimal READ/WRITE policy gate, and a
plan → approve → execute → verify loop over the *existing*
``RequestRouter`` (see ``src/neuralbridge/core/router.py``). It does not
invent a second dispatch path to adapters, and it does not call out to an
LLM: the "AI" in this slice is a deterministic capability router over
tools the platform already exposes, not a system of record. Every fact it
shows the user is read straight off a ``RequestRouter``/adapter response
and carries the connection, tool, timestamp and request id that produced
it — see ``schemas.Provenance``.
"""

from __future__ import annotations
