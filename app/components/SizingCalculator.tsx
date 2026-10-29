'use client';

import { useMemo, useState } from 'react';
import { SALES } from '../lib/links';
import { CASES_NOT_METERED, FALLBACK_PLANS, type PlanLimits } from '../lib/plans';

// Which tier covers what you need — derived from the plan data itself
// (app/lib/plans.ts, a verbatim copy of what src/assurance/billing/plans.py
// serves), never from names typed here. Each need names the plan flag that
// gates it; the recommendation is the first plan whose limits grant every flag
// the ticked needs require. tests/test_assurance_plans_parity.py checks each
// flag below against the routes that really carry that gate. There is no volume
// cap to size against: cases are not metered on any tier, so this asks what you
// need to do, never "how many".

type NeedKey = 'machine' | 'annex3' | 'fleet' | 'change' | 'attest';
type Gate = 'register_access' | 'machine_verification' | 'signed_attestation';

const NEEDS: { key: NeedKey; label: string; gate: Gate }[] = [
  { key: 'machine', gate: 'machine_verification', label: 'Machine safety verification (ISO/TS 15066 checks against a safety envelope)' },
  { key: 'annex3', gate: 'machine_verification', label: 'Machinery Annex III manifests and passports' },
  { key: 'fleet', gate: 'machine_verification', label: 'Fleet advisory fan-out across enrolled machines' },
  { key: 'change', gate: 'machine_verification', label: 'Change-assurance cases (open, claim, submit re-verification evidence; human-decided closure, over /v1/change/*)' },
  { key: 'attest', gate: 'signed_attestation', label: 'Counter-signed head attestation (needs a service signing key; none is configured on any deployment today)' },
];

type Recommendation = { tier: string; reason: string };

const grants = (limits: PlanLimits, gate: Gate): boolean => limits[gate] === true;

function recommend(needsRegister: boolean, needs: Set<NeedKey>): Recommendation {
  const required = new Set<Gate>(NEEDS.filter((n) => needs.has(n.key)).map((n) => n.gate));
  if (needsRegister) required.add('register_access');
  const covering = FALLBACK_PLANS.filter((p) => [...required].every((g) => grants(p.limits, g)));
  const plan = covering[0] ?? FALLBACK_PLANS[FALLBACK_PLANS.length - 1];
  if (required.size === 0) {
    const cap = plan.limits.validations_per_day;
    return {
      tier: plan.name,
      reason: `No register needed yet — ${plan.name} covers Article 14 draft validation and the calculators, free${cap === null ? '' : `, with a ${cap}/day cap on validations`}.`,
    };
  }
  if (needs.size > 0) {
    const only = covering.length === 1;
    const these = needs.size === 1 ? 'this capability' : 'these capabilities';
    return {
      tier: plan.name,
      reason: only
        ? `${plan.name} is the only tier that includes ${these} — none of it is gated into the cheaper plans.`
        : `${plan.name} is the cheapest tier that includes ${these}.`,
    };
  }
  return {
    tier: plan.name,
    reason: `${plan.name} keeps the Article 14 register for one manufacturer: both deadline clocks and a hash-chained ledger with verifiable export. ${CASES_NOT_METERED}.`,
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
          {result.tier !== FALLBACK_PLANS[0].name && (
            <a className="btn btn-outline" href={SALES}>Talk to sales</a>
          )}
        </div>
      </div>
      <p className="calc-footnote">
        Derived from which capabilities each plan gates in <code>src/assurance/billing/plans.py</code> (see{' '}
        <code>docs/claims-registry.md</code>). There is no volume to size — cases are not metered. Prices are
        launch hypotheses, not validated with paying customers.
      </p>
    </div>
  );
}
