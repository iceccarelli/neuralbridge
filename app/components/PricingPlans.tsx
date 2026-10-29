'use client';

import { useEffect, useState } from 'react';
import { DEPLOY_BLOB, QUICKSTART, SALES, SALES_SUPPLIER } from '../lib/links';
import { FALLBACK_PLANS, type Plan } from '../lib/plans';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

type PaidTier = 'register' | 'cell' | 'payg';

// "€390 / month" -> amount and period, straight from the plan the API served.
// Nothing about a price is typed into this file: it is whatever plans.py says.
function Price({ price }: { price: string }) {
  if (price.toLowerCase() === 'free') return <p className="price-amount">Free</p>;
  const [amount, period] = price.split(' / ');
  return (
    <p className="price-amount">
      {amount}
      {period ? <span> / {period}</span> : null}
    </p>
  );
}

function CheckoutForm({
  tier,
  label,
  variant = 'primary',
}: {
  tier: PaidTier;
  label: string;
  variant?: 'primary' | 'secondary';
}) {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const btnClass = variant === 'primary' ? 'btn btn-primary' : 'btn btn-secondary';

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
      <button className={btnClass} onClick={() => setOpen(true)}>
        {tier === 'payg' ? `Start ${label}` : `Buy ${label}`}
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
      <button className={btnClass} onClick={submit} disabled={busy}>
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
        // The three standing plans must all be present; a fourth (pay as you go)
        // appears only when the deployment has configured it, and is rendered
        // only from this live list, never from the static fallback.
        const tiers = new Set(Array.isArray(data) ? data.map((p) => p.tier) : []);
        if (!cancelled && ['free', 'register', 'cell'].every((t) => tiers.has(t as Plan['tier']))) {
          setPlans(data);
          setLive(true);
        }
      })
      .catch(() => {
        /* stay on the static fallback — app/lib/plans.ts, copied from plans.py */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const byTier = (t: Plan['tier']) => plans.find((p) => p.tier === t) ?? FALLBACK_PLANS.find((p) => p.tier === t)!;
  const validator = byTier('free');
  const register = byTier('register');
  const cell = byTier('cell');
  // Never defaulted from FALLBACK_PLANS: if the API did not list it, it is not on sale.
  const payg = live ? plans.find((p) => p.tier === 'payg') : undefined;

  // Derived from the live plan's own `limits`, not hand-typed — so this
  // sentence cannot drift from what the entitlement gate actually enforces
  // (see src/assurance/billing/plans.py + neuralbridge.ai.entitlements).
  const firstTenMinutes = (plan: Plan): string | null => {
    const parts: string[] = [];
    if (plan.limits.register_access) parts.push('open a real Article 14 case');
    if (plan.limits.ai_control_plane) parts.push('unlock /ai’s write path (plan → approve → receipt)');
    if (parts.length === 0) return null;
    return `First 10 minutes: ${parts.join(', and ')} — with one key, no live checkout required to try it locally (see docs/buyer-journey.md).`;
  };

  return (
    <>
      <div className="pricing-grid">
        <div className="price-card">
          <p className="price-name">{validator.name}</p>
          <Price price={validator.price} />
          <p className="price-tagline">{validator.blurb}</p>
          <ul className="price-list">
            {validator.includes.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          <a className="btn btn-secondary" href={QUICKSTART}>
            Get the quickstart
          </a>
        </div>

        <div className="price-card featured">
          <p className="price-name">{register.name}</p>
          <Price price={register.price} />
          <p className="price-tagline">{register.blurb}</p>
          <ul className="price-list">
            {register.includes.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          {firstTenMinutes(register) && <p className="pricing-note" style={{ fontSize: '0.78rem' }}>{firstTenMinutes(register)}</p>}
          {register.purchasable ? (
            <CheckoutForm tier="register" label={register.name} />
          ) : (
            <a className="btn btn-primary" href={SALES}>Talk to sales</a>
          )}
        </div>

        <div className="price-card">
          <p className="price-name">{cell.name}</p>
          <Price price={cell.price} />
          <p className="price-tagline">{cell.blurb}</p>
          <ul className="price-list">
            {cell.includes.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          {firstTenMinutes(cell) && <p className="pricing-note" style={{ fontSize: '0.78rem' }}>{firstTenMinutes(cell)}</p>}
          {cell.purchasable ? (
            <CheckoutForm tier="cell" label={cell.name} variant="secondary" />
          ) : (
            <a className="btn btn-secondary" href={SALES}>Talk to sales</a>
          )}
        </div>
      </div>
      {payg && (
        <div className="pricing-grid" style={{ gridTemplateColumns: 'minmax(0, 1fr)', maxWidth: '28rem' }}>
          <div className="price-card" id="payg">
            <p className="price-name">{payg.name}</p>
            <Price price={payg.price} />
            <p className="price-tagline">{payg.blurb}</p>
            <ul className="price-list">
              {payg.includes.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
            {payg.purchasable && <CheckoutForm tier="payg" label={payg.name.toLowerCase()} variant="secondary" />}
          </div>
        </div>
      )}
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
