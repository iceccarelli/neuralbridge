#!/usr/bin/env python3
"""Fail a test run whose skips are not all explained.

    python scripts/check_test_skips.py JUNIT.xml [--allow REGEX ...] [--max-allowed N]

A skip is a gate that did not run. The Python job of CI runs without ``node_modules`` on purpose
(the Site job installs them and runs the same Node-dependent tests with NEURALBRIDGE_REQUIRE_NODE=1,
where a skip is a failure), so those skips are expected there. This script prints every skip reason
with its count and exits 1 if ANY skip is not covered by an --allow pattern (default: the two
messages the Node-dependent test modules use), so a new, unexplained skip cannot hide in the job's
"N skipped" tail. It never turns a skip into a pass: it only classifies.

Exit: 0 every skip is an allowed one | 1 at least one unexplained skip, or more allowed skips than
--max-allowed | 2 the report could not be read.
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET  # noqa: S405 - our own pytest junit file, not untrusted input
from collections import Counter

#: The reasons the Node-dependent modules (test_site_repo_links, test_site_product_pages,
#: test_site_seo) give when node_modules or node is absent. See tests/require_postgres_plugin.py.
DEFAULT_ALLOW = (r"node_modules is not installed", r"node is not installed")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("junit")
    ap.add_argument("--allow", action="append", default=None, help="regex a skip reason may match")
    ap.add_argument("--max-allowed", type=int, default=None,
                    help="fail if more than this many allowed skips occur (guards against the allowance growing silently)")
    args = ap.parse_args(argv)
    allow = [re.compile(p, re.IGNORECASE) for p in (args.allow or DEFAULT_ALLOW)]
    try:
        root = ET.parse(args.junit).getroot()  # noqa: S314
    except (OSError, ET.ParseError) as exc:
        print(f"cannot read {args.junit}: {type(exc).__name__}", file=sys.stderr)
        return 2

    total = skipped = 0
    explained: Counter[str] = Counter()
    unexplained: Counter[str] = Counter()
    for case in root.iter("testcase"):
        total += 1
        sk = case.find("skipped")
        if sk is None:
            continue
        skipped += 1
        reason = (sk.get("message") or sk.text or "").strip().splitlines()[0][:200] if (sk.get("message") or sk.text) else "(no reason)"
        bucket = explained if any(p.search(reason) for p in allow) else unexplained
        bucket[reason] += 1

    print(f"{total} tests in the report, {skipped} skipped")
    for reason, n in explained.most_common():
        print(f"  allowed    {n:5d}  {reason}")
    for reason, n in unexplained.most_common():
        print(f"  UNEXPLAINED {n:4d}  {reason}")
    n_allowed = sum(explained.values())
    if unexplained:
        print("FAIL: skips that are not explained above are gates that did not run.", file=sys.stderr)
        return 1
    if args.max_allowed is not None and n_allowed > args.max_allowed:
        print(f"FAIL: {n_allowed} allowed skips > --max-allowed {args.max_allowed}", file=sys.stderr)
        return 1
    if n_allowed:
        print(f"{n_allowed} allowed skips: Node-dependent tests; they run, and a skip is a failure, in the Site job.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
