"""The evidence report: everything in the ledger, on one page somebody can read.

Every other output in this package is terminal text, which means the only person
who ever sees it is an engineer at a prompt. The people who decide whether this
gets bought — a plant manager, a quality director, an insurer, a notified body,
the customer's procurement — do not open terminals. They read documents, and
they forward them.

So this renders one self-contained HTML file. No network, no fonts to fetch, no
scripts to run: it opens on a laptop in a plant with no internet, it prints, it
attaches to an email, and it goes in a tender response unchanged.

Three things the layout enforces, because they are the difference between a
report that is trusted and one that is filed:

**The chain verification is the first thing on the page.** If the ledger does not
verify, everything below it is drawn from a store whose integrity is in
question, and saying so at the bottom would be a lie of placement.

**Findings are ordered by what somebody has to do today**, not by machine name.
A cell whose evidence lapsed seven months ago outranks four cells that are fine.

**"What this does not establish" is a numbered section, not a footnote.** Every
``checks_skipped`` line the engines produced is carried through verbatim. A
report that hides its own limits is worth less than no report, because somebody
will rely on it.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from assurance.core.identity import format_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.declaration import (
    DeclarationOfConformity,
    DeclarationStatus,
    check_declaration,
)
from assurance.fleet.impact import ImpactReport, assess_impact
from assurance.fleet.registry import Fleet

__all__ = ["ReportInput", "render_report"]


def e(value: Any) -> str:
    return html.escape(str(value), quote=True)


@dataclass(frozen=True)
class ReportInput:
    """Everything the report draws on. Only the ledger is required."""

    ledger: EvidenceLedger
    #: Organisation the report is about, as it should appear on the page.
    organisation: str = ""
    #: Who produced it.
    prepared_by: str = ""
    #: Optional advisory to fan out across the fleet.
    advisory: Any = None
    #: Declarations, keyed by machine key.
    declarations: tuple[DeclarationOfConformity, ...] = ()
    #: A banner shown at the very top, e.g. the demonstration-data notice.
    notice: str = ""
    generated_at: datetime | None = None


_CSS = """
:root{
  --ink:#14181a; --ink-2:#3d4745; --muted:#626d6a;
  --ground:#ffffff; --panel:#f4f6f3; --rule:#d2d7d2; --rule-firm:#a7b0ac;
  --accent:#0d6a6b; --accent-soft:#e3efee;
  --bad:#a11220; --bad-soft:#fbeaec;
  --warn:#8a5a06; --warn-soft:#fbf1dd;
  --good:#2c6535; --good-soft:#e7f0e7;
  --mono:ui-monospace,"SFMono-Regular",Menlo,Consolas,"Liberation Mono",monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);font-family:var(--sans);
     font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
.sheet{max-width:1000px;margin:0 auto;padding:0 20px 64px}
h1,h2,h3{margin:0;text-wrap:balance}
a{color:var(--accent)}
.mono{font-family:var(--mono);font-variant-numeric:tabular-nums}

header.masthead{padding:36px 0 18px;border-bottom:2px solid var(--ink);
  display:flex;flex-wrap:wrap;gap:14px 32px;align-items:flex-end}
.masthead h1{font-size:clamp(24px,4vw,34px);letter-spacing:-.01em;line-height:1.08}
.masthead .who{font-size:13px;color:var(--muted);margin-top:6px}
.masthead .meta{font-family:var(--mono);font-size:11.5px;color:var(--muted);
  margin-left:auto;text-align:right;line-height:1.7}

.banner{margin:18px 0 0;padding:12px 14px;border-left:4px solid var(--accent);
  background:var(--accent-soft);font-size:13.5px}
.banner.bad{border-color:var(--bad);background:var(--bad-soft);color:var(--bad);
  font-weight:600}
.banner.warn{border-color:var(--warn);background:var(--warn-soft)}
.banner b{font-weight:700}

.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:0;margin-top:22px;border:1px solid var(--rule)}
.tile{padding:14px 16px;border-right:1px solid var(--rule)}
.tile:last-child{border-right:0}
.tile .n{font-family:var(--mono);font-size:30px;line-height:1;font-weight:500;
  letter-spacing:-.02em}
.tile .k{font-size:11px;letter-spacing:.1em;text-transform:uppercase;
  color:var(--muted);margin-top:7px}
.tile.bad .n{color:var(--bad)} .tile.warn .n{color:var(--warn)}
.tile.good .n{color:var(--good)}

section{margin-top:38px;break-inside:auto}
section>h2{font-size:12px;letter-spacing:.14em;text-transform:uppercase;
  color:var(--muted);padding-bottom:8px;border-bottom:1px solid var(--rule-firm)}
section>.lede{margin:12px 0 0;color:var(--ink-2);max-width:72ch}

table{width:100%;border-collapse:collapse;font-size:13.5px;margin-top:14px}
th,td{text-align:left;padding:7px 10px;border-top:1px solid var(--rule);
  vertical-align:top}
thead th{font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;
  color:var(--muted);border-top:0;border-bottom:1px solid var(--rule-firm)}
td.n,th.n{text-align:right;font-family:var(--mono);font-variant-numeric:tabular-nums;
  white-space:nowrap}
tbody tr:hover{background:var(--panel)}
.wide{overflow-x:auto}

.pill{display:inline-block;font-size:10.5px;font-weight:700;letter-spacing:.07em;
  text-transform:uppercase;padding:2px 7px;border-radius:2px;white-space:nowrap}
.pill.current{background:var(--good-soft);color:var(--good)}
.pill.stale{background:var(--bad-soft);color:var(--bad)}
.pill.failing{background:var(--bad);color:#fff}
.pill.never_verified{background:var(--warn-soft);color:var(--warn)}
.pill.not_demonstrable{background:var(--panel);color:var(--muted);
  box-shadow:inset 0 0 0 1px var(--rule-firm)}
.pill.confirmed{background:var(--bad-soft);color:var(--bad)}
.pill.contradictory{background:var(--warn);color:#fff}
.pill.probable{background:var(--warn-soft);color:var(--warn)}
.pill.possible{background:var(--panel);color:var(--muted);
  box-shadow:inset 0 0 0 1px var(--rule-firm)}

.machine{border:1px solid var(--rule);margin-top:16px;break-inside:avoid}
.machine>header{display:flex;flex-wrap:wrap;gap:6px 18px;align-items:baseline;
  padding:12px 16px;background:var(--panel);border-bottom:1px solid var(--rule)}
.machine h3{font-size:16px}
.machine .site{color:var(--muted);font-size:13px}
.machine .cfg{margin-left:auto;font-family:var(--mono);font-size:11.5px;
  color:var(--muted)}
.machine .body{padding:4px 16px 14px}
.fn{padding:9px 0;border-top:1px solid var(--rule)}
.fn:first-child{border-top:0}
.fn .top{display:flex;flex-wrap:wrap;gap:4px 10px;align-items:baseline}
.fn .id{font-family:var(--mono);font-weight:600}
.fn .perf{font-family:var(--mono);font-size:11.5px;color:var(--muted)}
.fn .why{color:var(--ink-2);font-size:13px;margin-top:3px;max-width:78ch}
.fn .days{color:var(--bad);font-weight:600;font-size:13px;margin-top:3px}

.note{margin-top:12px;padding:10px 12px;border-left:3px solid var(--rule-firm);
  background:var(--panel);font-size:13px;color:var(--ink-2)}
.note.bad{border-color:var(--bad);background:var(--bad-soft)}
.note.warn{border-color:var(--warn);background:var(--warn-soft)}
.note b{color:var(--ink)}

ol.limits{margin:14px 0 0;padding-left:22px}
ol.limits li{margin-bottom:9px;color:var(--ink-2);max-width:80ch}

footer{margin-top:44px;padding-top:16px;border-top:1px solid var(--rule);
  font-size:12px;color:var(--muted);max-width:80ch}
footer code{font-family:var(--mono);font-size:11.5px;background:var(--panel);
  padding:1px 5px;border:1px solid var(--rule)}
footer p{margin:0 0 8px}

@media print{
  body{font-size:11pt}
  .sheet{max-width:none;padding:0}
  section{break-inside:auto}
  .machine,.tiles,.banner,.note{break-inside:avoid}
  tbody tr:hover{background:none}
  header.masthead{padding-top:0}
}
"""

_COVERAGE_WORDS = {
    "current": "Current",
    "stale": "Stale",
    "failing": "Failing",
    "never_verified": "Never verified",
    "not_demonstrable": "Not demonstrable",
}


def _tile(value: Any, label: str, tone: str = "") -> str:
    return (f'<div class="tile {tone}"><div class="n">{e(value)}</div>'
            f'<div class="k">{e(label)}</div></div>')


def _fleet_table(fleet: Fleet) -> str:
    rows = sorted(fleet.records,
                  key=lambda r: (r.worst.rank if r.worst else 99, -r.stale_count,
                                 r.machine_key))
    body = []
    for r in rows:
        worst = r.worst.value if r.worst else "—"
        body.append(
            f"<tr><td class='mono'>{e(r.machine_key)}</td>"
            f"<td>{e(r.site or '—')}</td>"
            f"<td><span class='pill {e(worst)}'>"
            f"{e(_COVERAGE_WORDS.get(worst, worst))}</span></td>"
            f"<td class='n'>{r.stale_count}</td>"
            f"<td class='n'>{len(r.coverage.functions)}</td>"
            f"<td class='n'>{len(r.interventions)}</td>"
            f"<td class='n'>{len(r.verifications)}</td>"
            f"<td class='mono'>{e(r.manifest.configuration_hash()[:12])}</td>"
            f"<td class='mono'>{e(r.manifest.taken_at.date().isoformat())}</td></tr>")
    return (
        "<div class='wide'><table><thead><tr>"
        "<th>Machine</th><th>Site</th><th>Weakest function</th>"
        "<th class='n'>Stale</th><th class='n'>Functions</th>"
        "<th class='n'>Changes</th><th class='n'>Verifications</th>"
        "<th>Configuration</th><th>Last collected</th>"
        "</tr></thead><tbody>" + "".join(body) + "</tbody></table></div>")


def _machine_block(record: Any, status: DeclarationStatus | None) -> str:
    m = record.manifest
    out = [
        "<article class='machine'><header>",
        f"<h3 class='mono'>{e(m.machine.serial)}</h3>",
        f"<span class='site'>{e(m.machine.manufacturer)} {e(m.machine.model)}"
        + (f" · {e(m.machine.site)}" if m.machine.site else "") + "</span>",
        f"<span class='cfg'>config {e(m.configuration_hash()[:16])} · "
        f"{len(m.items)} item(s) · tier {e(m.tier_ceiling.value)}</span>",
        "</header><div class='body'>",
    ]
    for f in sorted(record.coverage.functions,
                    key=lambda f: (f.coverage.rank, f.function_id)):
        days = f.days_uncovered
        out.append(
            "<div class='fn'><div class='top'>"
            f"<span class='id'>{e(f.function_id)}</span>"
            f"<span>{e(f.description)}</span>"
            + (f"<span class='perf'>{e(f.required_performance)}</span>"
               if f.required_performance else "")
            + f"<span class='pill {e(f.coverage.value)}'>"
              f"{e(_COVERAGE_WORDS[f.coverage.value])}</span></div>"
            f"<div class='why'>{e(f.detail)}</div>"
            + (f"<div class='days'>Running {days} day(s) without valid evidence "
               "for this function.</div>" if days is not None else "")
            + "</div>")

    if record.interventions:
        rows = "".join(
            f"<tr><td class='mono'>{e(i.intervention_id)}</td>"
            f"<td class='mono'>{e(format_utc(i.occurred_at)[:10])}</td>"
            f"<td class='mono'>{e(i.item_id)}</td>"
            f"<td>{e(i.performed_by.identifier)}</td>"
            f"<td>{e(i.reason)}</td>"
            f"<td>{'yes' if i.is_authorised else '<b>no</b>'}</td>"
            f"<td>{'yes' if i.is_revalidated else '<b>no</b>'}</td></tr>"
            for i in record.interventions)
        out.append(
            "<div class='wide'><table><thead><tr><th>Change</th><th>When</th>"
            "<th>Item</th><th>By</th><th>Reason</th><th>Authorised</th>"
            "<th>Re-run</th></tr></thead><tbody>" + rows + "</tbody></table></div>")

    if status is not None:
        tone = "" if status.is_sound else "bad"
        out.append(f"<div class='note {tone}'><b>{e(status.doc_id)}</b> — "
                   f"{e(status.verdict.value.replace('_', ' '))}. "
                   f"{e(status.statement)}</div>")
    out.append("</div></article>")
    return "".join(out)


def _impact_block(impact: ImpactReport) -> str:
    head = {
        "clear": ("", "No machine in this fleet matches this advisory."),
        "exposed": ("bad", "Standing safety evidence is now in question."),
        "needs_review": ("warn", "Matches found; none had standing evidence."),
    }[impact.verdict]
    out = [
        f"<div class='banner {head[0]}'><b>{e(impact.advisory_id)}</b> "
        f"({e(impact.issued_by)}, {e(impact.severity.value.replace('_', ' '))}) — "
        f"{e(head[1])}<br>{e(impact.title)}<br>"
        f"<span class='mono'>{e(impact.reference)}</span></div>",
        "<div class='wide'><table><thead><tr><th>Machine</th><th>Site</th>"
        "<th>Item</th><th>Version</th><th>Basis</th><th>What it rests on</th>"
        "<th>Functions now in question</th></tr></thead><tbody>",
    ]
    order = {"hash": 0, "hash_mismatch": 1, "version": 2, "name_only": 3}
    for x in sorted(impact.exposures,
                    key=lambda x: (order[x.basis.value], x.machine_key)):
        newly = ", ".join(f.function_id for f in x.newly_in_question) or "—"
        out.append(
            f"<tr><td class='mono'>{e(x.machine_key)}</td>"
            f"<td>{e(x.site or '—')}</td>"
            f"<td class='mono'>{e(x.item_id)}</td>"
            f"<td class='mono'>{e(x.item_version or '—')}</td>"
            f"<td><span class='pill {e(x.confidence)}'>{e(x.confidence)}</span></td>"
            f"<td>{e(x.detail)}</td>"
            f"<td class='mono'>{e(newly)}</td></tr>")
    out.append("</tbody></table></div>")
    if impact.contradictory:
        out.append(
            "<div class='note warn'><b>Counted in neither column.</b> "
            f"{len(impact.contradictory)} machine(s) report a version the advisory "
            "names while the artefact contradicts the supplier's own published "
            "hash. They are not confirmed affected and not confirmed clear. "
            "Somebody has to look at those machines.</div>")
    return "".join(out)


def render_report(data: ReportInput) -> str:
    """Produce one self-contained HTML page. No network, no scripts."""
    fleet = Fleet.from_ledger(data.ledger)
    generated = data.generated_at or utc_now()
    declarations = {d.machine_key: d for d in data.declarations}

    impact: ImpactReport | None = None
    if data.advisory is not None:
        impact = assess_impact(data.advisory, fleet)

    statuses: dict[str, DeclarationStatus] = {}
    for record in fleet.records:
        doc = declarations.get(record.machine_key)
        if doc is not None:
            statuses[record.machine_key] = check_declaration(
                doc, record.manifest, record.coverage)

    stale = sum(r.stale_count for r in fleet.records)
    uncovered = sum(len(r.coverage.uncovered) for r in fleet.records)
    functions = sum(len(r.coverage.functions) for r in fleet.records)
    unsound = sum(1 for s in statuses.values() if not s.is_sound)

    parts: list[str] = [
        "<title>Machine safety evidence report</title>",
        f"<style>{_CSS}</style>",
        "<div class='sheet'>",
        "<header class='masthead'><div>",
        "<h1>Machine safety evidence report</h1>",
        "<div class='who'>"
        + (f"{e(data.organisation)} · " if data.organisation else "")
        + f"{len(fleet)} machine(s) · {functions} declared safety function(s)"
        + (f" · prepared by {e(data.prepared_by)}" if data.prepared_by else "")
        + "</div></div>",
        f"<div class='meta'>generated {e(format_utc(generated))}<br>"
        f"ledger {e(str(data.ledger.path.name))} · {len(data.ledger)} sealed "
        f"record(s)</div></header>",
    ]

    if data.notice:
        parts.append(f"<div class='banner warn'>{e(data.notice)}</div>")

    # The integrity statement is the first thing on the page, always.
    if fleet.chain_verified:
        head = data.ledger.head_attestation()
        parts.append(
            "<div class='banner'><b>Ledger chain verifies.</b> "
            f"All {len(data.ledger)} record(s) hash to their recorded values and "
            "each links to the one before it. Head "
            f"<span class='mono'>{e(str(head.get('head_link_hash', ''))[:24])}</span>."
            "</div>")
    else:
        parts.append(
            "<div class='banner bad'><b>THE LEDGER CHAIN DOES NOT VERIFY.</b> "
            "Every statement in this report is drawn from a store whose integrity "
            "is in question. "
            + e("; ".join(fleet.chain_problems[:3])) + "</div>")

    parts.append("<div class='tiles'>")
    parts.append(_tile(len(fleet), "machines"))
    parts.append(_tile(functions - uncovered, "functions covered",
                       "good" if uncovered == 0 else ""))
    parts.append(_tile(stale, "stale", "bad" if stale else ""))
    parts.append(_tile(uncovered - stale, "otherwise uncovered",
                       "warn" if uncovered - stale else ""))
    if impact is not None:
        parts.append(_tile(len(impact.machines_affected), "advisory matches",
                           "bad" if impact.machines_affected else "good"))
    if statuses:
        parts.append(_tile(unsound, "declarations in doubt",
                           "bad" if unsound else "good"))
    parts.append("</div>")

    if impact is not None:
        parts.append("<section><h2>1 · Component advisory</h2>")
        parts.append("<p class='lede'>A supplier has published an advisory. This is "
                     "every machine in the ledger it touches, and the safety "
                     "functions whose evidence it unsettles.</p>")
        parts.append(_impact_block(impact))
        parts.append("</section>")

    n = 2 if impact is not None else 1
    parts.append(f"<section><h2>{n} · Fleet</h2>")
    parts.append("<p class='lede'>Weakest function first, because that is the order "
                 "somebody acts in. “Stale” means a recorded change to safety-relevant "
                 "software invalidated a verification that had passed.</p>")
    parts.append(_fleet_table(fleet))
    parts.append("</section>")

    parts.append(f"<section><h2>{n + 1} · Machine by machine</h2>")
    for record in sorted(fleet.records,
                         key=lambda r: (r.worst.rank if r.worst else 99,
                                        r.machine_key)):
        parts.append(_machine_block(record, statuses.get(record.machine_key)))
    parts.append("</section>")

    # Everything the engines said they could not establish, verbatim.
    limits: list[str] = []
    seen: set[str] = set()
    for record in fleet.records:
        for c in record.coverage.checks_skipped:
            if c not in seen:
                seen.add(c)
                limits.append(c)
    if impact is not None:
        for c in impact.checks_skipped:
            if c not in seen:
                seen.add(c)
                limits.append(c)
    for s in statuses.values():
        for c in s.checks_skipped:
            if c not in seen:
                seen.add(c)
                limits.append(c)

    parts.append(f"<section><h2>{n + 2} · What this report does not establish</h2>")
    parts.append("<p class='lede'>Carried verbatim from the engines that produced "
                 "the findings above. A report that hides its own limits is worth "
                 "less than no report, because somebody will rely on it.</p>")
    parts.append("<ol class='limits'>"
                 + "".join(f"<li>{e(c)}</li>" for c in limits) + "</ol>")
    parts.append("</section>")

    parts.append(
        "<footer>"
        "<p><b>How to check this without trusting whoever sent it.</b> Every finding "
        "above comes from a hash-chained ledger. Run "
        "<code>assurance machinery check &lt;passport&gt; --ledger &lt;register.db&gt;</code> "
        "against the ledger this was generated from: it re-runs the engine on the "
        "original records and reports any statement that does not reproduce.</p>"
        "<p>Coverage joins verification bundles to intervention records through the "
        "safety functions the manifest declares. A verification is dated by when the "
        "run happened, not when it was filed. A function that declares no "
        "verification check is reported as not demonstrable, never as covered.</p>"
        "<p>Nothing in this report is legal advice. Whether a changed configuration "
        "amounts to a substantial modification requiring a new conformity assessment "
        "is a question for the manufacturer and, where one is involved, the notified "
        "body.</p>"
        "</footer></div>")

    return "".join(parts)
