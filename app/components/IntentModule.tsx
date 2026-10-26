'use client';

import { useState } from 'react';
import { IMAGES } from '../lib/images';
import { platformStatusText } from '../lib/platformStatus';
import RotatingImage from './RotatingImage';

interface Intent {
  key: string;
  label: string;
  solutionSlug: string;
  proofTitle: string;
  proofBody: string;
  /** Run in order from the repository root; the last one produced `output`. `register.db` is any scratch path. */
  commands: string[];
  output: string;
}

// Each "output" block is an EXCERPT of what the shipped command printed on this repository's
// synthetic example files (examples/). Every line shown is a whole line of the real output, in
// order. A line that is only "…" marks lines left out; "… N more not shown" follows the shown
// lines of a "not checked" list and says how many of its lines are left out.
//
// tests/test_site_honesty.py re-runs the commands in `commands` (and the API call for the
// validator) and fails if a line shown is not in the output, if the verdict line is not first, if a
// failing or never-run line is hidden, if the first line of a "not checked" or "provenance" section
// is hidden, or if an N is wrong. The "sealed as <id>" line is left out because the id changes with
// the date of the run. The README status table is not command output: it renders from
// app/lib/platformStatus.ts, which the same test compares with README.md.
const INTENTS: Intent[] = [
  {
    key: 'manufacturing',
    label: 'I want to… check a supplier advisory against my fleet',
    solutionSlug: 'manufacturer',
    proofTitle: 'Fleet advisory, matched by hash',
    proofBody: 'One advisory, fanned out to every enrolled serial — matched by hash, with the unsigned-feed warning kept.',
    commands: [
      'assurance machinery record-manifest examples/machinery/manifest-baseline.json --ledger register.db',
      'assurance fleet advisory examples/fleet/advisory-CTRL-2026-11.json --ledger register.db',
    ],
    output: `CTRL-2026-11 — Watchdog may not trip under sustained safety-bus load
  !! INSPECT ONLY — trust state unauthenticated_file: this advisory did not meet the trust policy, so nothing below may drive a stop-use or a case as a trusted supplier statement
CTRL-2026-11 (ControlCo, safety_relevant) — NEEDS REVIEW — matches found, none with standing evidence
  1 of 1 machine(s) match; 0 safety function(s) newly in question
  Grimaldi/AR-7#0412   Plant 2, Line 4   [confirmed] ITM-FW 3.8.2
      the artefact on this machine is byte-identical to one ControlCo named as affected (aaaaaaaaaaaa).
      SF-01  Protective stop on zone intrusion  (coverage already never verified)
      SF-02  Speed limit in collaborative operation  (coverage already never verified)
  not checked:
    - 1 machine(s) carry at least one item with no hash. An affected component hiding in an unhashed item would not be found by this assessment.
    - 1 machine(s) are known only from a declared baseline (Grimaldi/AR-7#0412): what is installed on them was never observed, so a match or a clear here is about the paperwork.
  … 1 more not shown
  provenance:
    - This advisory is not signed, or its signature was not checked. It arrived as a file. Acting on it means changing a safety system on the authority of something anyone could have written — which is the attack this mechanism exists to prevent. Ask the supplier to publish a signed feed; it costs them one command.`,
  },
  {
    key: 'robotics',
    label: 'I want to… verify a machine’s safety envelope',
    solutionSlug: 'manufacturer',
    proofTitle: 'Machine safety verification, worst-margin first',
    proofBody: 'A recorded run checked against a declared envelope — including the failures.',
    commands: [
      'assurance machine verify --envelope examples/machine/envelope.json --trace examples/machine/trace.json --actor docs-example',
    ],
    output: `AR-7 Palletising Cell 2.4.1 — FAIL at tier profile
  [ok  ] workspace_containment (250 samples)  worst margin 300.0 mm
  [FAIL] speed_limit (250 samples)  worst shortfall 1050.0 mm/s
           t=1.000s measured 1800.0 > 750.0 mm/s (by 1050.0)
…
  [FAIL] ssm_separation (130 samples)  worst shortfall 1281.0 mm
           t=1.000s measured 2400.0 < 3225.2 mm (by 825.2)
…
  [FAIL] stop_characterisation (130 samples)  worst shortfall 1300.0 mm/s
           t=1.000s measured 1800.0 > 500.0 mm/s (by 1300.0)
…
  This result may NOT be used to claim how the hardware behaves.
  The trace's provenance ('field') is the filer's own declaration; no recorder attestation was accepted under a trust list this verifier holds, so it does not lift the tier above community.
  not checked:
    - 130 samples ran at a speed above the one the stopping distance was measured at (500 mm/s). Ss for those samples is a constant-deceleration model, not a measurement.
  … 6 more not shown`,
  },
  {
    key: 'compliance',
    label: 'I want to… file an Article 14 report correctly',
    solutionSlug: 'compliance-officer',
    proofTitle: 'The free validator, catching a real mistake',
    proofBody: 'A draft submission checked against the 39-field spec before you open the platform.',
    commands: [
      'POST /v1/spec/validate {"track": "actively_exploited_vulnerability", "stage": "early_warning", "payload": {"product_name": "AR-7 Palletising Cell", "member_states_available": ["DE", "CH"]}}',
    ],
    output: `"submittable": false,
"issues": [
  { "field_number": "v26", "field_name": "awareness_datetime",
    "message": "required at this stage but absent. The fact every deadline runs from." },
  { "field_number": "5", "field_name": "member_states_available",
    "message": "['CH'] are not EU Member States." }
  … and 4 more
]`,
  },
  {
    key: 'insurance',
    label: 'I want to… verify evidence someone else produced',
    solutionSlug: 'insurer-auditor',
    proofTitle: 'Coverage: which safety functions have evidence',
    proofBody: 'Which declared safety functions have never had a verification, and which intervention has nothing re-run.',
    commands: [
      'assurance machinery record-manifest examples/machinery/manifest-baseline.json --ledger register.db',
      'assurance machinery record-change examples/machinery/intervention-0007.json --ledger register.db',
      'assurance machinery coverage examples/machinery/manifest-as-found.json --ledger register.db',
    ],
    output: `Grimaldi/AR-7#0412 — GAPS
  [never ] SF-01 [PL d]  Protective stop on zone intrusion
           no verification in the ledger has ever run ssm_separation, stop_characterisation for this machine.
  [never ] SF-02 [PL d]  Speed limit in collaborative operation
           no verification in the ledger has ever run speed_limit for this machine.
  Interventions on safety-bearing items with nothing re-run: INT-0007
  not checked:
    - 1 manifest item(s) carry no hash, so a change to them would not appear in a divergence report and would only reach this assessment if somebody wrote an intervention record by hand.
  … 2 more not shown`,
  },
  {
    key: 'ai-ops',
    label: 'I want to… connect AI agents to real systems',
    solutionSlug: 'ai-ops',
    proofTitle: 'What is actually supported today',
    proofBody: 'The README’s status table, word for word — not a roadmap dressed as a feature.',
    commands: ['README.md — Current Supported Scope'],
    output: platformStatusText(),
  },
];

export default function IntentModule() {
  const [active, setActive] = useState(INTENTS[0].key);
  const intent = INTENTS.find((i) => i.key === active) ?? INTENTS[0];

  return (
    <div className="intent-module">
      <RotatingImage
        slot={IMAGES['intent-fleet-advisory']}
        aspect="21/9"
        sizes="100vw"
        className="pricing-media"
      />
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
          {intent.commands.map((command) => (
            <p className="intent-proof-source" key={command}>
              {/^assurance /.test(command) ? '$ ' : ''}
              {command}
            </p>
          ))}
        </div>
        <div className="hero-code intent-output">{intent.output}</div>
      </div>

      <a className="btn btn-primary" href={`/solutions/${intent.solutionSlug}`}>
        See the full solution &rarr;
      </a>
    </div>
  );
}
