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
    Article14Duty,
    FeedSubscription,
    WatchConfig,
    WatchError,
    WatchTarget,
)
from assurance.watch.filings import (
    ARTICLE_14_WINDOW,
    FILING_KIND,
    FilingPrompt,
    FilingsPass,
    draft_filings,
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
    "ARTICLE_14_WINDOW",
    "Article14Duty",
    "FILING_KIND",
    "FilingPrompt",
    "FilingsPass",
    "draft_filings",
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
