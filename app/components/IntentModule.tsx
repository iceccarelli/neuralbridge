'use client';

import { useState } from 'react';

interface Intent {
  key: string;
  label: string;
  solutionSlug: string;
  proofTitle: string;
  proofBody: string;
  output: string;
  source: string;
}

// Every "output" block below is a real terminal capture from this
// session's own verification of the shipped engines — not a mockup, not
// stock content. Re-run the command in `source` yourself to reproduce it.
const INTENTS: Intent[] = [
  {
    key: 'manufacturing',
    label: 'I want to… check a supplier advisory against my fleet',
    solutionSlug: 'manufacturer',
    proofTitle: 'Fleet advisory, matched by hash',
    proofBody: 'One advisory, fanned out to every enrolled serial — confirmed, not guessed.',
    source: 'assurance fleet advisory advisory-CTRL-2026-11.json --ledger register.db',
    output: `CTRL-2026-11 (ControlCo, safety_relevant) — NEEDS REVIEW
  Grimaldi/AR-7#0412   Plant 2, Line 4   [confirmed] ITM-FW 3.8.2
      the artefact on this machine is byte-identical to one
      ControlCo named as affected (aaaaaaaaaaaa).
      SF-01  Protective stop on zone intrusion
      SF-02  Speed limit in collaborative operation

  provenance:
    - This advisory is not signed, or its signature was not
      checked. Ask the supplier to publish a signed feed.`,
  },
  {
    key: 'robotics',
    label: 'I want to… verify a machine’s safety envelope',
    solutionSlug: 'manufacturer',
    proofTitle: 'Machine safety verification, worst-margin first',
    proofBody: 'A recorded run checked against a declared envelope — including the failures.',
    source: 'assurance machine verify --envelope envelope.json --trace trace.json',
    output: `AR-7 Palletising Cell 2.4.1 — FAIL at tier profile
  [ok  ] workspace_containment (250 samples)  worst margin 300.0 mm
  [FAIL] speed_limit (250 samples)  worst margin 0.0 mm/s
           t=1.000s measured 1800.0 > 750.0 mm/s (by 1050.0)
  [FAIL] ssm_separation (130 samples)  worst margin 7.0 mm
  This result may NOT be used to claim how the hardware behaves.
  sealed as d996d2d676a66f82 (3 stated limitations)`,
  },
  {
    key: 'compliance',
    label: 'I want to… file an Article 14 report correctly',
    solutionSlug: 'compliance-officer',
    proofTitle: 'The free validator, catching a real mistake',
    proofBody: 'A draft submission checked against the 39-field spec before you open the platform.',
    source: 'POST /v1/spec/validate',
    output: `"submittable": false,
"issues": [
  { "field_number": "v26", "field_name": "awareness_datetime",
    "message": "required at this stage but absent. The fact
                every deadline runs from." },
  { "field_number": "5", "field_name": "member_states_available",
    "message": "['CH'] are not EU Member States." }
]`,
  },
  {
    key: 'insurance',
    label: 'I want to… verify evidence someone else produced',
    solutionSlug: 'insurer-auditor',
    proofTitle: 'The staleness join',
    proofBody: 'A February sign-off, a March change, and which safety functions stopped being covered.',
    source: 'assurance machinery coverage manifest-as-found.json --ledger register.db',
    output: `Grimaldi/AR-7#0412 — GAPS
  [never ] SF-01 [PL d]  Protective stop on zone intrusion
           no verification in the ledger has ever run
           ssm_separation, stop_characterisation for this machine.
  Interventions on safety-bearing items with nothing re-run: INT-0007`,
  },
  {
    key: 'ai-ops',
    label: 'I want to… connect AI agents to real systems',
    solutionSlug: 'ai-ops',
    proofTitle: 'What is actually supported today',
    proofBody: 'The platform status table — Supported vs Evolving, not a roadmap dressed as a feature.',
    source: 'GET /v1/plans and the README’s own status table',
    output: `FastAPI backend                              Supported
Connection management model                  Supported
MCP tool listing / invocation                 Supported
Small set of working adapters (PostgreSQL,
REST)                                         Supported
Broad adapter ecosystem                       Evolving
Full enterprise compliance posture            Evolving`,
  },
];

export default function IntentModule() {
  const [active, setActive] = useState(INTENTS[0].key);
  const intent = INTENTS.find((i) => i.key === active) ?? INTENTS[0];

  return (
    <div className="intent-module">
      <label className="intent-label" htmlFor="intent-select">What are you trying to do?</label>
      <select
        id="intent-select"
        className="intent-select"
        value={active}
        onChange={(e) => setActive(e.target.value)}
      >
        {INTENTS.map((i) => (
          <option key={i.key} value={i.key}>{i.label}</option>
        ))}
      </select>

      <div className="intent-proof">
        <div>
          <span className="intent-proof-kicker">{intent.proofTitle}</span>
          <p className="intent-proof-body">{intent.proofBody}</p>
          <p className="intent-proof-source">$ {intent.source}</p>
        </div>
        <div className="hero-code intent-output">{intent.output}</div>
      </div>

      <a className="btn btn-primary" href={`/solutions/${intent.solutionSlug}`}>
        See the full solution &rarr;
      </a>
    </div>
  );
}
