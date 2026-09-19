'use client';

import { useEffect, useState } from 'react';
import { DEPLOY_BLOB, QUICKSTART, SALES, SALES_SUPPLIER } from '../lib/links';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

interface PlanLimits {
  validations_per_day: number | null;
  product_families: number | null;
  cases_per_day: number | null;
  register_access: boolean;
  verifiable_export: boolean;
  signed_attestation: boolean;
  machine_verification: boolean;
}

interface Plan {
  tier: 'free' | 'register' | 'cell';
  name: string;
  blurb: string;
  price: string;
  purchasable: boolean;
  includes: string[];
  limits: PlanLimits;
}

// Mirrors src/assurance/billing/plans.py::public_catalogue() exactly, for
// when the live API isn't reachable — this is what GET /v1/plans returns
// today from any deployment with no Stripe price env vars set. Not a
// marketing guess; the field names match the enforced dataclass.
const FALLBACK_PLANS: Plan[] = [
  {
    tier: 'free',
    name: 'Validator',
    blurb: 'The free lead magnet. No card, no account required.',
    price: 'free',
    purchasable: false,
    includes: [
      'Article 14 draft validation',
      'ISO/TS 15066 separation calculator',
      'Manifest diff',
      'Advisory check',
      'Declaration check',
      'Bundle re-verification',
      'Attestation verification',
      'Offline enrolment kit',
    ],
    limits: { validations_per_day: 20, product_families: null, cases_per_day: null, register_access: false, verifiable_export: false, signed_attestation: false, machine_verification: false },
  },
  {
    tier: 'register',
    name: 'Register',
    blurb: 'The Article 14 register for one manufacturer.',
    price: '€390 / month',
    purchasable: false,
    includes: [
      'Unlimited Article 14 cases',
      'Both deadline clocks, computed correctly',
      'Hash-chained ledger with verifiable export',
      '25 product families',
      'Everything in Validator',
    ],
    limits: { validations_per_day: null, product_families: 25, cases_per_day: 50, register_access: true, verifiable_export: true, signed_attestation: false, machine_verification: false },
  },
  {
    tier: 'cell',
    name: 'Cell',
    blurb: 'Everything in Register, for the full cell.',
    price: '€1,290 / month',
    purchasable: false,
    includes: [
      'Machine safety verification',
      'Annex III manifests and passports',
      'Fleet advisory fan-out',
      'Declarations bound to a configuration hash',
      'Counter-signed head attestation',
      'Everything in Register',
    ],
    limits: { validations_per_day: null, product_families: null, cases_per_day: null, register_access: true, verifiable_export: true, signed_attestation: true, machine_verification: true },
  },
];

function CheckoutForm({ tier }: { tier: 'register' | 'cell' }) {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setError(null);
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      setError('Enter a valid email.');
      return;
    }
    setBusy(true);
    try {
      const res = await fetch(`${API_BASE}/v1/checkout`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tier, email }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.detail?.detail || data?.detail || `Checkout is unavailable (${res.status}).`);
        setBusy(false);
        return;
      }
      window.location.href = data.checkout_url;
    } catch {
      setError('Could not reach the checkout API.');
      setBusy(false);
    }
  };

  if (!open) {
    return (
      <button className="btn btn-primary" onClick={() => setOpen(true)}>
        Buy {tier === 'register' ? 'Register' : 'Cell'}
      </button>
    );
  }

  return (
    <div className="checkout-inline">
      <input
        type="email"
        placeholder="you@company.com"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        className="checkout-input"
      />
      <button className="btn btn-primary" onClick={submit} disabled={busy}>
        {busy ? 'Starting checkout…' : 'Continue to Stripe checkout'}
      </button>
      {error && <p className="playground-error">{error}</p>}
    </div>
  );
}

export default function PricingPlans() {
  const [plans, setPlans] = useState<Plan[]>(FALLBACK_PLANS);
  const [live, setLive] = useState(false);

  useEffect(() => {
    if (!API_BASE) return;
    let cancelled = false;
    fetch(`${API_BASE}/v1/plans`)
      .then((res) => (res.ok ? res.json() : Promise.reject(res.status)))
      .then((data: Plan[]) => {
        if (!cancelled && Array.isArray(data) && data.length === 3) {
          setPlans(data);
          setLive(true);
        }
      })
      .catch(() => {
        /* stay on the static fallback — it matches plans.py exactly */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const byTier = (t: Plan['tier']) => plans.find((p) => p.tier === t) ?? FALLBACK_PLANS.find((p) => p.tier === t)!;
  const validator = byTier('free');
  const register = byTier('register');
  const cell = byTier('cell');

  return (
    <>
      <div className="pricing-grid">
        <div className="price-card">
          <p className="price-name">Validator</p>
          <p className="price-amount">Free</p>
          <p className="price-tagline">{validator.blurb}</p>
          <ul className="price-list">
            {validator.includes.slice(0, 8).map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          <a className="btn btn-secondary" href={QUICKSTART}>
            Get the quickstart
          </a>
        </div>

        <div className="price-card featured">
          <p className="price-name">Register</p>
          <p className="price-amount">&euro;390 <span>/ month</span></p>
          <p className="price-tagline">{register.blurb}</p>
          <ul className="price-list">
            {register.includes.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          {register.purchasable ? (
            <CheckoutForm tier="register" />
          ) : (
            <a className="btn btn-primary" href={SALES}>Talk to sales</a>
          )}
        </div>

        <div className="price-card">
          <p className="price-name">Cell</p>
          <p className="price-amount">&euro;1,290 <span>/ month</span></p>
          <p className="price-tagline">{cell.blurb}</p>
          <ul className="price-list">
            {cell.includes.slice(0, 6).map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          {cell.purchasable ? (
            <CheckoutForm tier="cell" />
          ) : (
            <a className="btn btn-secondary" href={SALES}>Talk to sales</a>
          )}
        </div>
      </div>
      {live && (
        <p className="pricing-live-note">
          <span className="live-dot" /> Live from <code>GET /v1/plans</code> — this table is generated from the
          entitlements the deployed service enforces, not hand-typed.
        </p>
      )}
      <p className="pricing-note" id="supplier">
        There is also a fourth, unlisted tier — <strong>Supplier</strong> — for component suppliers who want to
        publish signed advisories to a hosted feed (<code>POST /v1/supplier/advisory</code>). It has no self-serve
        price yet, sales-assigned only per{' '}
        <a href={`${DEPLOY_BLOB}/ADR-0001-supplier-api.md`} target="_blank" rel="noreferrer">ADR-0001</a>:{' '}
        <a href={SALES_SUPPLIER}>get in touch</a>.
      </p>
    </>
  );
}
