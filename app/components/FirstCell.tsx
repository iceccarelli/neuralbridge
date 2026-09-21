'use client';

import { useState } from 'react';
import { CELL_VERIFY_FIXTURE } from '../lib/cellVerifyFixture';

// A guided path to the one call that proves a Cell key is real:
// POST /v1/machine/verify — mirrors FirstCase.tsx's honesty rules exactly.
//
// Unlike /v1/cases/{id}/signal (Anyone can call it; Register/Cell decide
// whether it writes), this route is gated by the `Machine` dependency
// (require_machine in src/assurance/api/deps.py) directly on the door: no
// key at all is a real 401 ("This endpoint needs an API key"), and a real
// but under-tier key (free or Register) is a real 402
// ("plan_does_not_include_machine_verification") — there is no free preview
// of a pass/fail verdict the way the register has a free read side. Only a
// Cell key gets past the door. This component calls that route directly
// over fetch(), no server-side process of its own, and shows exactly the
// status/body the API returned — never a faked success.
//
// The envelope/trace in the request body are a bundled fixture (see
// ../lib/cellVerifyFixture — generated from the real SafetyEnvelope/Trace
// classes, the same objects tests/test_assurance_machine.py exercises), not
// something typed into this form: proving the wire path needs a
// self-consistent recorded run, and a visitor pasting numbers by hand would
// usually produce a 422 (schema/consistency errors) that proves nothing
// about their key. Actor/role come from what they type. A real integration
// posts its own machine's recorded trace, not this fixture.
type VerifyOut = {
  verdict: string;
  tier: string;
  sealed: boolean;
  may_claim_physical_behaviour: boolean;
  evidence?: { content_hash?: string };
};

type Result =
  | { kind: 'success'; data: VerifyOut }
  | { kind: 'unauthorized'; message: string }
  | { kind: 'upgrade'; tier: string; remedy: string }
  | { kind: 'error'; status: number; message: string };

export default function FirstCell({ apiBase, apiKey }: { apiBase: string; apiKey: string }) {
  const [actorId, setActorId] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result | null>(null);

  const submit = async () => {
    setResult(null);
    if (!apiBase) return;
    setBusy(true);
    try {
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (apiKey) headers['X-API-Key'] = apiKey;
      const res = await fetch(`${apiBase}/v1/machine/verify`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          ...CELL_VERIFY_FIXTURE,
          actor: actorId.trim() || 'console-user',
          role: 'verification engineer',
          seal: true,
        }),
      });
      const body = await res.json().catch(() => null);
      if (res.status === 200) {
        setResult({ kind: 'success', data: body as VerifyOut });
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
          remedy: detail?.remedy || 'Machine safety verification is included from the Cell plan upward.',
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
    <div className="ai-card" id="cell-verify">
      <div className="ai-card-title">
        <span className="status-pill cell">First Cell verification</span>
      </div>
      <p style={{ fontSize: '0.85rem', color: 'var(--ink-soft)' }}>
        The same check <code>POST /v1/machine/verify</code> runs from{' '}
        <a href="https://github.com/iceccarelli/neuralbridge/blob/main/tests/test_assurance_machine.py">
          tests/test_assurance_machine.py
        </a>
        , called live from this page against a bundled sample run (a clean SSM pass — see{' '}
        <code>app/lib/cellVerifyFixture.ts</code> for exactly what it sends). Paste your Cell key above and press the
        button: this compares that recorded run against its declared safety envelope for real, using the real
        engine, and seals the result to the hash-chained ledger. No key, a free-tier key, or a Register-tier key
        gets the real refusal below — this route has no free preview, unlike the register — never a faked pass. Real
        integration posts a caller&apos;s own recorded trace in place of the fixture.
      </p>

      <div className="first-case-form">
        <label htmlFor="fcell-actor">Your identifier (optional)</label>
        <input
          id="fcell-actor"
          value={actorId}
          onChange={(e) => setActorId(e.target.value)}
          placeholder="e.g. you@company.com"
          autoComplete="off"
        />
      </div>

      <button className="btn btn-primary" onClick={submit} disabled={busy}>
        {busy ? 'Verifying…' : 'Verify the sample run'}
      </button>

      {result?.kind === 'success' && (
        <div className="console-response" style={{ marginTop: '0.75rem' }}>
          <span className={`playground-verdict ${result.data.verdict === 'pass' ? 'ok' : 'blocked'}`}>
            HTTP 200 — verdict: {result.data.verdict}
          </span>
          <p style={{ fontSize: '0.85rem' }}>
            Tier <strong>{result.data.tier}</strong>;{' '}
            {result.data.may_claim_physical_behaviour
              ? 'this run may claim physical behaviour — field provenance against measured stop figures.'
              : 'this run may NOT claim physical behaviour — the verifier itself withheld that claim.'}{' '}
            {result.data.sealed
              ? 'Sealed to the hash-chained evidence ledger.'
              : 'Not sealed to the ledger (seal was not requested).'}
          </p>
          {result.data.evidence?.content_hash && (
            <p style={{ fontSize: '0.85rem' }}>
              <code>content_hash</code>{' '}
              <span style={{ fontFamily: 'monospace' }}>{result.data.evidence.content_hash.slice(0, 16)}…</span> —
              from the real engine's bundle, not an echo of what was sent.
            </p>
          )}
        </div>
      )}

      {result?.kind === 'unauthorized' && (
        <div className="console-response" style={{ marginTop: '0.75rem' }}>
          <span className="playground-verdict blocked">HTTP 401 — {result.message}</span>
          <p style={{ fontSize: '0.85rem' }}>
            No key, or the key was rejected outright. Paste a valid Cell key in the field above, or{' '}
            <a href="/#pricing">see pricing</a> to get one.
          </p>
        </div>
      )}

      {result?.kind === 'upgrade' && (
        <div className="ai-card ai-upgrade-card" style={{ marginTop: '0.75rem' }}>
          <span className="status-pill cell">Cell required</span>
          <p style={{ fontSize: '0.85rem' }}>
            Your key is real, but its plan (<strong>{result.tier}</strong>) does not include machine safety
            verification. {result.remedy}
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
            Not a live checkout in this message — no charge happens here. Once you have a Cell key, paste it into
            the field above and press &ldquo;Verify the sample run&rdquo; again — nothing you typed here is lost.
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
