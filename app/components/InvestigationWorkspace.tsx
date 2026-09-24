'use client';

import { useState } from 'react';
import { useSharedApiKey } from '../lib/apiKey';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

// The Machine Assurance Investigation: the Cell-tier view over a machine
// already enrolled in the ledger. This calls the same POST
// /v1/check/fleet-machine the MCP tool and the API docs use — no second
// business-logic layer, no frontend-only simulation. Every section below is
// a real field from that one response.

type FunctionCoverage = {
  function_id: string;
  description: string;
  coverage: string;
  last_verified_at: string;
  invalidated_by: string;
  invalidated_at: string;
  invalidating_item: string;
  detail: string;
};

type InterventionRow = {
  intervention_id: string;
  occurred_at: string;
  performed_by: string;
  kind: string;
  item_id: string;
  affects_functions: string[];
  revalidated: boolean;
};

type ConfigurationChange = { item_id: string; kind: string; severity: string; name: string; detail: string };

type InvestigationResult = {
  machine: string;
  verdict: string;
  enrolled: boolean;
  advisory_evaluated: boolean;
  affected: boolean;
  configuration: { status: 'matched' | 'changed' | 'unknown'; changes: ConfigurationChange[] };
  matches: { item_id: string; item_name: string; item_version: string; confidence: string; needs_a_human: boolean; detail: string }[];
  functions: FunctionCoverage[];
  evidence: { valid: number; stale: number; insufficient: number; cannot_determine: number };
  required_actions: string[];
  human_review_required: boolean;
  interventions: InterventionRow[];
  latest_intervention: InterventionRow | null;
  fleet: { machines_analyzed: number | null; machines_affected: number | null } | null;
  commercial_next_action: { action: string; endpoint: string | null };
  assessed_at: string;
  checks_skipped: string[];
};

type Refusal =
  | { kind: 'auth'; message: string }
  | { kind: 'payment'; requiredPlan: string; remedy: string }
  | { kind: 'not_enrolled'; message: string }
  | { kind: 'error'; status: number; message: string };

const VERDICT_LABEL: Record<string, string> = {
  no_impact_found: 'NO IMPACT FOUND',
  potentially_affected: 'POTENTIALLY AFFECTED',
  requires_reverification: 'REQUIRES RE-VERIFICATION',
  requires_human_review: 'REQUIRES HUMAN REVIEW',
  insufficient_evidence: 'INSUFFICIENT EVIDENCE',
  cannot_determine: 'CANNOT DETERMINE',
  verified: 'VERIFIED',
};

const CONFIG_LABEL: Record<string, string> = {
  matched: 'Matches declared baseline',
  changed: 'Differs from declared baseline',
  unknown: 'No declared baseline sealed',
};

export default function InvestigationWorkspace() {
  const { key: apiKey, setKey: setApiKey } = useSharedApiKey();
  const [machineKey, setMachineKey] = useState('Grimaldi/AR-7#0412');
  const [advisoryJson, setAdvisoryJson] = useState('');
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [refusal, setRefusal] = useState<Refusal | null>(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setRefusal(null);
    setResult(null);
    if (!API_BASE) {
      setRefusal({ kind: 'error', status: 0, message: 'No API URL configured for this deployment — see /status.' });
      return;
    }
    if (!machineKey.trim()) {
      setRefusal({ kind: 'error', status: 0, message: 'Enter the machine key this machine was enrolled under, e.g. Grimaldi/AR-7#0412.' });
      return;
    }
    let advisory: unknown;
    if (advisoryJson.trim()) {
      try {
        advisory = JSON.parse(advisoryJson);
      } catch {
        setRefusal({ kind: 'error', status: 0, message: 'The advisory is not valid JSON — leave it blank to check the machine’s current state alone.' });
        return;
      }
    }
    setLoading(true);
    try {
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (apiKey) headers['X-API-Key'] = apiKey;
      const res = await fetch(`${API_BASE}/v1/check/fleet-machine`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ machine_key: machineKey.trim(), ...(advisory ? { advisory } : {}) }),
      });
      const body = await res.json().catch(() => null);
      if (res.status === 200) {
        setResult(body as InvestigationResult);
      } else if (res.status === 401) {
        setRefusal({ kind: 'auth', message: body?.detail?.detail || body?.detail || 'This needs an API key.' });
      } else if (res.status === 402) {
        const d = body?.detail || {};
        setRefusal({ kind: 'payment', requiredPlan: d.required_plan || 'cell', remedy: d.remedy || 'Upgrade to continue.' });
      } else if (res.status === 404) {
        setRefusal({ kind: 'not_enrolled', message: body?.detail?.detail || 'This machine has not been enrolled yet.' });
      } else {
        setRefusal({ kind: 'error', status: res.status, message: body?.detail?.detail || body?.detail || `The service answered ${res.status}.` });
      }
    } catch {
      setRefusal({ kind: 'error', status: 0, message: 'Could not reach the API host.' });
    }
    setLoading(false);
  };

  return (
    <div className="console-shell">
      <div className="key-row">
        <label htmlFor="inv-api-key">API key (Cell plan)</label>
        <input
          id="inv-api-key"
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder="paste your Cell-plan API key"
          autoComplete="off"
          spellCheck={false}
        />
      </div>

      <div className="first-case-form">
        <label htmlFor="inv-machine-key">Machine key</label>
        <input
          id="inv-machine-key"
          value={machineKey}
          onChange={(e) => setMachineKey(e.target.value)}
          placeholder="Grimaldi/AR-7#0412"
          autoComplete="off"
          spellCheck={false}
        />
        <label htmlFor="inv-advisory">Advisory to check against this machine (optional — leave blank to read its current standing evidence alone)</label>
        <textarea
          id="inv-advisory"
          value={advisoryJson}
          onChange={(e) => setAdvisoryJson(e.target.value)}
          rows={6}
          placeholder='{"advisory_id": "...", "issued_by": "...", ...}'
          spellCheck={false}
        />
      </div>

      <button className="btn btn-primary" onClick={run} disabled={loading}>
        {loading ? 'Investigating…' : 'Investigate this machine'}
      </button>

      {refusal?.kind === 'auth' && (
        <div className="console-response" style={{ marginTop: '0.75rem' }}>
          <span className="playground-verdict blocked">HTTP 401 — authentication required</span>
          <p style={{ fontSize: '0.85rem' }}>{refusal.message} Paste a Cell-plan key above, or <a href="/#pricing">see pricing</a>.</p>
        </div>
      )}
      {refusal?.kind === 'payment' && (
        <div className="ai-card ai-upgrade-card" style={{ marginTop: '0.75rem' }}>
          <span className="status-pill register">{refusal.requiredPlan.toUpperCase()} plan required</span>
          <p style={{ fontSize: '0.85rem' }}>{refusal.remedy}</p>
          <p style={{ fontSize: '0.74rem', color: 'var(--ink-soft)' }}>
            Nothing you typed above is lost — once you have a Cell-plan key, paste it in and press &ldquo;Investigate this
            machine&rdquo; again.
          </p>
          <a className="btn btn-primary" href="/#pricing">See pricing</a>
        </div>
      )}
      {refusal?.kind === 'not_enrolled' && (
        <div className="console-response" style={{ marginTop: '0.75rem' }}>
          <span className="playground-verdict blocked">HTTP 404 — not enrolled</span>
          <p style={{ fontSize: '0.85rem' }}>{refusal.message} Seal a manifest first with <code>POST /v1/machinery/manifest</code>.</p>
        </div>
      )}
      {refusal?.kind === 'error' && <p className="playground-error" style={{ marginTop: '0.5rem' }}>{refusal.message}</p>}

      {result && (
        <div className="playground-result" style={{ marginTop: '1rem' }}>
          <span className={`playground-verdict ${result.affected ? 'blocked' : 'ok'}`}>
            {VERDICT_LABEL[result.verdict] ?? result.verdict.toUpperCase()} — {result.machine}
          </span>

          <div className="tile-grid" style={{ marginTop: '1rem' }}>
            <div className="tile">
              <h3>Machine</h3>
              <p>{result.machine}</p>
              <p style={{ fontSize: '0.8rem', color: 'var(--ink-soft)' }}>
                Configuration: {CONFIG_LABEL[result.configuration.status]}
              </p>
            </div>
            <div className="tile">
              <h3>Evidence</h3>
              <p>{result.evidence.valid} valid · {result.evidence.stale} stale</p>
              <p style={{ fontSize: '0.8rem', color: 'var(--ink-soft)' }}>
                {result.evidence.insufficient} insufficient · {result.evidence.cannot_determine} cannot determine
              </p>
            </div>
            {result.fleet && (
              <div className="tile">
                <h3>Fleet</h3>
                <p>{result.fleet.machines_affected} of {result.fleet.machines_analyzed} affected</p>
              </div>
            )}
            <div className="tile">
              <h3>Intervention history</h3>
              <p>{result.interventions.length} recorded</p>
              {result.latest_intervention && (
                <p style={{ fontSize: '0.8rem', color: 'var(--ink-soft)' }}>
                  latest: {result.latest_intervention.kind} on {result.latest_intervention.item_id},{' '}
                  {result.latest_intervention.occurred_at.slice(0, 10)}
                </p>
              )}
            </div>
          </div>

          {result.functions.length > 0 && (
            <>
              <h3 style={{ marginTop: '1.5rem' }}>Safety functions</h3>
              <ul className="playground-issues">
                {result.functions.map((f) => (
                  <li key={f.function_id}>
                    <strong>{f.function_id} — {f.coverage.toUpperCase()}</strong>
                    <span>{f.description}</span>
                    <span>{f.detail}</span>
                  </li>
                ))}
              </ul>
            </>
          )}

          {result.interventions.length > 0 && (
            <>
              <h3 style={{ marginTop: '1.5rem' }}>Timeline</h3>
              <ul className="playground-issues">
                {result.interventions.map((i) => (
                  <li key={i.intervention_id}>
                    <strong>{i.occurred_at.slice(0, 10)} — {i.kind}</strong>
                    <span>{i.item_id} by {i.performed_by}{i.revalidated ? ' (revalidated)' : ' (not revalidated)'}</span>
                  </li>
                ))}
              </ul>
            </>
          )}

          {result.checks_skipped.length > 0 && (
            <p style={{ fontSize: '0.78rem', color: 'var(--ink-soft)', marginTop: '1rem' }}>{result.checks_skipped[0]}</p>
          )}

          <div className="ai-card" style={{ marginTop: '1rem' }}>
            <span className="status-pill register">Next: {result.commercial_next_action.action.replace(/_/g, ' ')}</span>
            {result.commercial_next_action.endpoint && (
              <p style={{ fontSize: '0.85rem' }}>
                Calls <code>{result.commercial_next_action.endpoint}</code>.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
