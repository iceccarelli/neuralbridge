'use client';

import type { Me } from '../../lib/assuranceApi';
import { PanelFrame } from './PanelFrame';
import type { Panel } from './usePanel';

const LIMIT_LABELS: Record<string, string> = {
  validations_per_day: 'Article 14 validations per day',
  register_access: 'Article 14 register',
  verifiable_export: 'Verifiable evidence export',
  signed_attestation: 'Signed ledger-head attestation',
  machine_verification: 'Machine verification, fleet and change assurance',
  separations_per_day: 'Separation calculations per day',
  diffs_per_day: 'Configuration diffs and advisory checks per day',
  supplier_publish: 'Hosted supplier feed',
  ai_control_plane: '/ai control plane',
  ai_reads_per_day: '/ai reads per day',
};

function limitValue(v: number | boolean | null): string {
  if (v === true) return 'included';
  if (v === false) return 'not included';
  if (v === null) return 'no daily cap';
  return String(v);
}

// A plan's `verifiable_export: false` is what the plan includes going forward. For an account
// whose subscription ended, GET /v1/me carries `evidence_readout`: the server still lets it
// export the evidence it already holds. The page shows that flag; it does not work it out.
function limitText(key: string, v: number | boolean | null, evidenceReadout: boolean): string {
  if (key === 'verifiable_export' && v === false && evidenceReadout) {
    return 'available for the evidence you already hold (read, verify and export only)';
  }
  return limitValue(v);
}

// What GET /v1/me says about this key: the plan the server enforces, what it includes, what
// has been used today, and the key prefixes on the account. Nothing here is computed on the
// page, and a key is never shown back.
export default function PlanPanel({ apiKey, me }: { apiKey: string; me: Panel<Me> }) {
  return (
    <PanelFrame id="aw-plan" title="Plan and usage" what="your plan" apiKey={apiKey} panel={me}>
      {(m) => (
        <>
          {!m.authenticated && (
            <p className="aw-note">
              The server did not recognise this as an account key; this is the free validator&apos;s allowance, not a
              plan.
            </p>
          )}
          <dl className="aw-kv">
            <dt>Plan</dt>
            <dd data-testid="plan-name">{m.plan.name}</dd>
            <dt>Tier</dt>
            <dd data-testid="plan-tier">{m.tier}</dd>
            {m.account && (
              <>
                <dt>Account</dt>
                <dd>
                  {m.account.company || m.account.email} (<code>{m.account.id}</code>)
                </dd>
                <dt>Status</dt>
                <dd data-testid="plan-status">{m.account.status}</dd>
              </>
            )}
          </dl>
          {m.warning && (
            <div className="aw-alert" role="alert" data-testid="plan-warning">
              {m.warning}
            </div>
          )}
          <h3>What this plan includes</h3>
          <ul data-testid="plan-includes">
            {m.plan.includes.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
          <h3>Limits the server enforces</h3>
          <ul data-testid="plan-limits">
            {Object.entries(m.plan.limits).map(([k, v]) => (
              <li key={k} data-testid={`plan-limit-${k}`}>
                {LIMIT_LABELS[k] ?? k}: {limitText(k, v, m.evidence_readout === true)}
              </li>
            ))}
          </ul>
          {m.evidence_readout === true && (
            <p className="aw-note" data-testid="plan-readout-note">
              Your subscription has ended. The server still lets you read, verify and export the evidence you
              already hold; new records and operational views are closed.
            </p>
          )}
          <h3>Used today</h3>
          <p data-testid="plan-usage">
            {Object.keys(m.usage_today).length === 0
              ? 'Nothing metered has been used today. Change-assurance cases and fleet reads are not metered.'
              : Object.entries(m.usage_today)
                  .map(([scope, n]) => `${scope}: ${n}`)
                  .join(' · ')}
          </p>
          {m.keys && (
            <>
              <h3>Keys on this account</h3>
              <ul data-testid="plan-keys">
                {m.keys.map((k, i) => (
                  <li key={`${k.prefix}-${i}`}>
                    <code>{k.prefix}…</code> {k.label ? `— ${k.label}` : ''} {k.created_at ? `· created ${k.created_at}` : ''}
                    {k.revoked_at ? ` · revoked ${k.revoked_at}` : ''}
                  </li>
                ))}
                {m.keys.length === 0 && <li>None.</li>}
              </ul>
              <p className="aw-note">Only the first characters of a key are ever shown. A lost key cannot be recovered.</p>
            </>
          )}
        </>
      )}
    </PanelFrame>
  );
}
