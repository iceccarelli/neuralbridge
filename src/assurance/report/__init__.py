"""The report: everything in the ledger, on one page somebody who isn't an
engineer at a terminal can actually read, print, and forward.

    demo     a complete worked fleet, built from nothing, in one command
    render   one self-contained HTML page — no network, no scripts, prints

The report is the product surface for everyone who signs the cheque.
"""

from assurance.report.demo import DEMO_NOTICE, DemoFleet, build_demo
from assurance.report.render import ReportInput, render_report

__all__ = [
    "DEMO_NOTICE",
    "DemoFleet",
    "ReportInput",
    "build_demo",
    "render_report",
]
