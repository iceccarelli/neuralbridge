"""The offline enrolment kit: the first thing a customer ever runs.

    airgap   a guard over the socket layer, and a record of what it saw
    enrol    one command, inside the plant, producing their ledger and report

Everything else in this package assumes somebody has already decided to adopt
it. This is the part that runs before that decision, on their disk, with the
network provably untouched — because a claim a plant's IT department can check
is a different object from a claim they cannot.
"""

from assurance.kit.airgap import (
    AIRGAP_LIMITS,
    AirgapError,
    AirgapResult,
    NetworkAttempt,
    no_network,
)
from assurance.kit.enrol import (
    AIRGAP_KIND,
    KIT_RUN_KIND,
    KitConfig,
    KitError,
    KitRun,
    MachineEntry,
    MachineResult,
    run_kit,
    starter_config,
)

__all__ = [
    "AIRGAP_KIND",
    "AIRGAP_LIMITS",
    "AirgapError",
    "AirgapResult",
    "KIT_RUN_KIND",
    "KitConfig",
    "KitError",
    "KitRun",
    "MachineEntry",
    "MachineResult",
    "NetworkAttempt",
    "no_network",
    "run_kit",
    "starter_config",
]
