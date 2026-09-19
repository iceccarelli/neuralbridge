'use client';

import { useMemo, useState } from 'react';
import { SALES } from '../lib/links';

// Mirrors the entitlement flags actually enforced in
// src/assurance/billing/plans.py — not a marketing guess. If that file
// changes these numbers, this calculator drifts and should be updated
// alongside it (no separate source of truth to keep in sync automatically
// yet; see the pricing note below the plan cards for why).
const REGISTER_LIMITS = { productFamilies: 25, casesPerDay: 50 };

type NeedKey = 'machine' | 'annex3' | 'fleet' | 'attest';

const NEEDS: { key: NeedKey; label: string }[] = [
  { key: 'machine', label: 'Machine safety verification (ISO/TS 15066 checks against a safety envelope)' },
  { key: 'annex3', label: 'Machinery Annex III manifests and passports' },
  { key: 'fleet', label: 'Fleet advisory fan-out across enrolled machines' },
  { key: 'attest', label: 'Counter-signed head attestation' },
];

type Recommendation = { tier: 'Validator' | 'Register' | 'Cell'; reason: string };

function recommend(productFamilies: number, casesPerDay: number, needs: Set<NeedKey>): Recommendation {
  if (needs.size > 0) {
    return {
      tier: 'Cell',
      reason: `Cell is the only tier that includes ${Array.from(needs).length === 1 ? 'this' : 'these'} capabilit${needs.size === 1 ? 'y' : 'ies'} — none of it is gated into Register.`,
    };
  }
  if (productFamilies > REGISTER_LIMITS.productFamilies || casesPerDay > REGISTER_LIMITS.casesPerDay) {
    return {
      tier: 'Cell',
      reason: `Register caps at ${REGISTER_LIMITS.productFamilies} product families and ${REGISTER_LIMITS.casesPerDay} cases/day; Cell is uncapped on both.`,
    };
  }
  if (productFamilies > 0 || casesPerDay > 0) {
    return {
      tier: 'Register',
      reason: `${productFamilies} product famil${productFamilies === 1 ? 'y' : 'ies'} and up to ${casesPerDay} case(s)/day fit inside Register's ${REGISTER_LIMITS.productFamilies}-family, ${REGISTER_LIMITS.casesPerDay}-case/day ceiling.`,
    };
  }
  return {
    tier: 'Validator',
    reason: 'No register access needed yet — Validator covers Article 14 draft validation and the calculators, free, with a 20/day cap.',
  };
}

export default function SizingCalculator() {
  const [productFamilies, setProductFamilies] = useState(1);
  const [casesPerDay, setCasesPerDay] = useState(1);
  const [needs, setNeeds] = useState<Set<NeedKey>>(new Set());

  const result = useMemo(
    () => recommend(productFamilies, casesPerDay, needs),
    [productFamilies, casesPerDay, needs],
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
      <div className="calc-panel-title">Which tier fits? Answer three questions.</div>
      <div className="calc-grid">
        <label className="calc-field">
          <span>Product families you manage</span>
          <input
            type="number"
            min={0}
            value={productFamilies}
            onChange={(e) => setProductFamilies(Math.max(0, Number(e.target.value) || 0))}
          />
        </label>
        <label className="calc-field">
          <span>Article 14 cases per day, at peak</span>
          <input
            type="number"
            min={0}
            value={casesPerDay}
            onChange={(e) => setCasesPerDay(Math.max(0, Number(e.target.value) || 0))}
          />
        </label>
      </div>

      <div className="calc-needs">
        <span className="calc-needs-label">Do you need any of these?</span>
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
        Computed from the same limits <code>src/assurance/billing/plans.py</code> enforces — 25 product families and
        50 cases/day on Register, machine verification / Annex III / fleet advisory / attestation gated to Cell only.
        Not a lead-gen guess.
      </p>
    </div>
  );
}
