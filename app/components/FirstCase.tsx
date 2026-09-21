'use client';

import { useState } from 'react';

// A guided path to the one call that proves a Register/Cell key is real:
// POST /v1/cases/{case_id}/signal — the same route
// docs/buyer-journey.md and tests/test_ai_buyer_journey.py exercise with
// curl/pytest. This component calls that route directly over fetch(), with
// no server-side process of its own — same honesty rule as the rest of
// /console: no key configured, or a free-tier key, gets the real 401/402
// this deployment's API actually returns, never a faked success.
type RecordedOut = {
  case_id: string;
  content_hash: string;
  kind: string;
  ledger_seq: number;
  outstanding: string[];
};

type Result =
  | { kind: 'success'; data: RecordedOut }
  | { kind: 'unauthorized'; message: string }
  | { kind: 'upgrade'; tier: string; remedy: string }
  | { kind: 'error'; status: number; message: string };

function randomCaseId() {
  return `first-case-${Math.random().toString(36).slice(2, 8)}`;
}

export default function FirstCase({ apiBase, apiKey }: { apiBase: string; apiKey: string }) {
  const [caseId, setCaseId] = useState(() => randomCaseId());
  const [productName, setProductName] = useState('');
  const [description, setDescription] = useState('');
  const [actorId, setActorId] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result | null>(null);

  const submit = async () => {
    setResult(null);
    if (!apiBase) return;
    if (!description.trim()) {
      setResult({ kind: 'error', status: 0, message: 'Describe what was reported — that field is required by the API.' });
      return;
    }
    setBusy(true);
    try {
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (apiKey) headers['X-API-Key'] = apiKey;
      const res = await fetch(`${apiBase}/v1/cases/${encodeURIComponent(caseId)}/signal`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          received_at: new Date().toISOString(),
          channel: 'customer_or_integrator',
          description: description.trim(),
          product_name: productName.trim(),
          actor: { identifier: actorId.trim() || 'console-user', role: 'operator' },
        }),
      });
      const body = await res.json().catch(() => null);
      if (res.status === 201) {
        setResult({ kind: 'success', data: body as RecordedOut });
      } else if (res.status === 401) {
        setResult({
          kind: 'unauthorized',
          message: typeof body?.detail === 'string' ? body.detail : 'This route needs an API key.',
        });
      } else if (res.status === 402) {
        const detail = body?.detail;
        setResult({
          kind: 'upgrade',
          tier: detail?.tier || 'free',
          remedy: detail?.remedy || 'The register is included from the Register plan upward.',
        });
      } else {
        const message =
          typeof body?.detail === 'string'
            ? body.detail
            : body?.detail?.detail || body?.detail?.error || `Refused (HTTP ${res.status}).`;
        setResult({ kind: 'error', status: res.status, message });
      }
    } catch {
      setResult({ kind: 'error', status: 0, message: 'Could not reach the API host — it may be down, or your network blocked the request.' });
    }
    setBusy(false);
  };

  if (!apiBase) return null;

  return (
    <div className="ai-card" id="first-case">
      <div className="ai-card-title">
        <span className="status-pill register">First Register case</span>
      </div>
      <p style={{ fontSize: '0.85rem', color: 'var(--ink-soft)' }}>
        The same write <a href="https://github.com/iceccarelli/neuralbridge/blob/main/docs/buyer-journey.md">
          docs/buyer-journey.md
        </a>{' '}
        walks through with curl — <code>POST /v1/cases/&#123;case_id&#125;/signal</code> — from this page. Paste
        your Register/Cell key above, fill in what was reported, and this opens a real case in the hash-chained
        ledger. No key, or a free-tier key, gets the real refusal below — never a faked success.
      </p>

      <div className="first-case-form">
        <label htmlFor="fc-case-id">Case ID</label>
        <input
          id="fc-case-id"
          value={caseId}
          onChange={(e) => setCaseId(e.target.value)}
          spellCheck={false}
          autoComplete="off"
        />

        <label htmlFor="fc-product">Product / machine (optional)</label>
        <input
          id="fc-product"
          value={productName}
          onChange={(e) => setProductName(e.target.value)}
          placeholder="e.g. Line 4 welder"
          autoComplete="off"
        />

        <label htmlFor="fc-actor">Your identifier (optional)</label>
        <input
          id="fc-actor"
          value={actorId}
          onChange={(e) => setActorId(e.target.value)}
          placeholder="e.g. you@company.com"
          autoComplete="off"
        />

        <label htmlFor="fc-description">What was reported</label>
        <textarea
          id="fc-description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          rows={3}
          placeholder="e.g. Unexpected outbound connection from the line controller"
        />
      </div>

      <button className="btn btn-primary" onClick={submit} disabled={busy}>
        {busy ? 'Recording…' : 'Open this case'}
      </button>

      {result?.kind === 'success' && (
        <div className="console-response" style={{ marginTop: '0.75rem' }}>
          <span className="playground-verdict ok">HTTP 201 — recorded on the register</span>
          <p style={{ fontSize: '0.85rem' }}>
            <code>content_hash</code> <span style={{ fontFamily: 'monospace' }}>{result.data.content_hash.slice(0, 16)}…</span>,{' '}
            <code>ledger_seq</code> {result.data.ledger_seq}. Both come from the real hash-chained ledger, not an
            echo of what you sent.
          </p>
          {result.data.outstanding.length > 0 && (
            <p style={{ fontSize: '0.82rem', color: 'var(--ink-soft)' }}>
              Outstanding next: {result.data.outstanding.join(', ')}.
            </p>
          )}
          <p style={{ fontSize: '0.85rem' }}>
            The same key also unlocks <a href="/ai">/ai</a>&apos;s write path — propose a write, approve it, get a
            real execution receipt.
          </p>
        </div>
      )}

      {result?.kind === 'unauthorized' && (
        <div className="console-response" style={{ marginTop: '0.75rem' }}>
          <span className="playground-verdict blocked">HTTP 401 — {result.message}</span>
          <p style={{ fontSize: '0.85rem' }}>
            No key, or the key was rejected outright. Paste a valid Register or Cell key in the field above, or{' '}
            <a href="/#pricing">see pricing</a> to get one.
          </p>
        </div>
      )}

      {result?.kind === 'upgrade' && (
        <div className="ai-card ai-upgrade-card" style={{ marginTop: '0.75rem' }}>
          <span className="status-pill register">Register or Cell required</span>
          <p style={{ fontSize: '0.85rem' }}>
            Your key is real, but its plan (<strong>{result.tier}</strong>) does not include the register. {result.remedy}
          </p>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <a className="btn btn-primary" href="/#pricing">
              See pricing
            </a>
            <a className="btn" href="/#pricing">
              Talk to sales
            </a>
          </div>
          <p style={{ fontSize: '0.74rem', color: 'var(--ink-soft)' }}>
            Not a live checkout in this message — no charge happens here. Once you have a Register/Cell key, paste
            it into the field above and press &ldquo;Open this case&rdquo; again — nothing you typed here is lost.
          </p>
        </div>
      )}

      {result?.kind === 'error' && (
        <p className="playground-error" style={{ marginTop: '0.5rem' }}>
          {result.message}
        </p>
      )}
    </div>
  );
}
