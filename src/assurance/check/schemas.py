"""The request models of the two Machine Assurance Check entry points.

Kept apart from :mod:`assurance.check.services` because they need pydantic, which the offline
command line does not otherwise require: the catalogue imports this module lazily, and the API
routes validate against exactly these classes, so the catalogue's ``input_schema`` is the
routes' own schema and cannot drift from it.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["FleetMachineCheckIn", "MachineCheckIn"]


class MachineCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: dict[str, Any]
    advisory: dict[str, Any]


class FleetMachineCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    machine_key: str = Field(min_length=1, max_length=300)
    advisory: dict[str, Any] | None = None
