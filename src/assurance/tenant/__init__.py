"""Operator tooling: export one customer account's data, then offboard it.

``python -m assurance tenant export|verify-export|delete``. Operator-only: it works on the data
volume and is not an HTTP route or an MCP tool. It deletes nothing on its own, on a schedule or
by default; retention periods are the operator's policy and this package does not apply one.
See ``deploy/assurance/TENANT.md``.
"""

from __future__ import annotations

__all__: list[str] = []
