"""Operator tooling: run the unattended steps of the pipeline as one auditable cycle.

``python -m assurance ops cycle|status|check``. This package schedules nothing and installs
nothing: it is the thing a timer (cron, systemd, a loop container) calls. It reuses the existing
verbs in-process (``intel refresh``, ``watch run``, ``attest anchor-all``,
``evidence.restore_check``) and implements none of their logic. See ``deploy/assurance/OPS.md``.
"""

from __future__ import annotations

__all__: list[str] = []
