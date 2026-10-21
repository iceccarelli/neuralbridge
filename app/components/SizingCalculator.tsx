'use client';

import { useMemo, useState } from 'react';
import { SALES } from '../lib/links';

// Which tier covers what you need — derived only from which capabilities each
// plan gates in src/assurance/billing/plans.py (register, export,
// machine_verification, signed_attestation, ...). There is no volume cap to
// size against: cases are not metered on any tier, so this asks what you need
// to do, never "how many".

type NeedKey = 'machine' | 'annex3' | 'fleet' | 'change' | 'attest';

const NEEDS: { key: NeedKey; label: string }[] = [
  { key: 'machine', label: 'Machine safety verification (ISO/TS 15066 checks against a safety envelope)' },
  { key: 'annex3', label: 'Machinery Annex III manifests and passports' },
  { key: 'fleet', label: 'Fleet advisory fan-out across enrolled machines' },
  { key: 'change', label: 'Change-assurance cases (open, claim, re-verify, close over /v1/change/*)' },
  { key: 'attest', label: 'Counter-signed head attestation' },
];

type Recommendation = { tier: 'Validator' | 'Register' | 'Cell'; reason: string };

function recommend(needsRegister: boolean, needs: Set<NeedKey>): Recommendation {
  if (needs.size > 0) {
    return {
      tier: 'Cell',
      reason: `Cell is the only tier that includes ${needs.size === 1 ? 'this' : 'these'} capabilit${needs.size === 1 ? 'y' : 'ies'} — none of it is gated into Register.`,
    };
  }
  if (needsRegister) {
    return {
      tier: 'Register',
      reason: 'Register keeps the Article 14 register for one manufacturer: both deadline clocks and a hash-chained ledger with verifiable export. Cases are not metered — no per-case cap or charge.',
    };
  }
  return {
    tier: 'Validator',
    reason: 'No register needed yet — Validator covers Article 14 draft validation and the calculators, free, with a 20/day cap on validations.',
  };
}

export default function SizingCalculator() {
  const [needsRegister, setNeedsRegister] = useState(true);
  const [needs, setNeeds] = useState<Set<NeedKey>>(new Set());

  const result = useMemo(
    () => recommend(needsRegister, needs),
    [needsRegister, needs],
  );

  const toggleNeed = (key: NeedKey) => {
    setNeeds((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  return (
    <div className="calc-panel">
      <div className="calc-panel-title">Which tier fits? Tick what you need.</div>
      <div className="calc-needs">
        <span className="calc-needs-label">Do you need to keep an Article 14 register?</span>
        <label className="calc-checkbox">
          <input type="checkbox" checked={needsRegister} onChange={() => setNeedsRegister((v) => !v)} />
          Yes — open and track Article 14 cases with both deadline clocks and an exportable ledger
        </label>
      </div>

      <div className="calc-needs">
        <span className="calc-needs-label">Do you also need any of these?</span>
        {NEEDS.map((n) => (
          <label className="calc-checkbox" key={n.key}>
            <input type="checkbox" checked={needs.has(n.key)} onChange={() => toggleNeed(n.key)} />
            {n.label}
          </label>
        ))}
      </div>

      <div className="calc-result">
        <span className="calc-result-tier">{result.tier}</span>
        <span className="calc-result-reason">{result.reason}</span>
        <div className="calc-result-actions">
          <a className="btn btn-primary" href="#pricing">See {result.tier} pricing</a>
          {result.tier !== 'Validator' && (
            <a className="btn btn-outline" href={SALES}>Talk to sales</a>
          )}
        </div>
      </div>
      <p className="calc-footnote">
        Derived from which capabilities each plan gates in <code>src/assurance/billing/plans.py</code> (see{' '}
        <code>docs/claims-registry.md</code>): the register on Register and Cell; machine verification, Annex III,
        fleet advisory, change-assurance cases and attestation on Cell only. There is no volume to size — cases
        are not metered. Prices are launch hypotheses, not validated with paying customers.
      </p>
    </div>
  );
}
