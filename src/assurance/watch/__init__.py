"""The watch: what runs when nobody is looking.

    config   the standing instruction — these machines, this cadence
    runner   one pass: collect, compare, seal only what moved, report what is new

Everything else in this package is invoked by somebody who already suspects
something. This is the component that finds a change on the day it happened.
"""

from assurance.watch.advisories import (
    ADVISORY_KIND,
    AdvisoryFinding,
    AdvisoryPass,
    FeedOutcome,
    check_feeds,
)
from assurance.watch.config import (
    FeedSubscription,
    WatchConfig,
    WatchError,
    WatchTarget,
)
from assurance.watch.runner import (
    OBSERVATION_KIND,
    RUN_KIND,
    MachineOutcome,
    WatchRun,
    last_run,
    run_watch,
)

__all__ = [
    "ADVISORY_KIND",
    "AdvisoryFinding",
    "AdvisoryPass",
    "FeedOutcome",
    "FeedSubscription",
    "check_feeds",
    "OBSERVATION_KIND",
    "RUN_KIND",
    "MachineOutcome",
    "WatchConfig",
    "WatchError",
    "WatchRun",
    "WatchTarget",
    "last_run",
    "run_watch",
]
