'use client';

import { useState } from 'react';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

// The Machine Assurance Check, free stage: one manifest, one advisory, no
// account. Field shapes mirror tests/test_assurance_check.py's fixtures
// exactly, so this payload is not a prop — it is a real ComponentAdvisory and
// a real SafetyManifest that POST /v1/check/machine actually parses and runs
// through the same match logic the paid, ledger-backed check uses.
const SAMPLE_PAYLOAD = `{
  "advisory": {
    "advisory_id": "CTRL-2026-11",
    "issued_by": "ControlCo",
    "issued_at": "2026-09-12T08:00:00Z",
    "title": "Watchdog may not trip under sustained bus load",
    "summary": "The watchdog can fail to trigger the safety-rated stop.",
    "severity": "safety_relevant",
    "affected": [
      {
        "supplier": "ControlCo",
        "name": "Safety controller firmware",
        "versions": ["3.8.0", "3.8.1", "3.8.2"],
        "content_hashes": ["1111111111111111111111111111111111111111111111111111111111111111"]
      }
    ],
    "remedy": "Update to 3.9.0 and re-run the stop-performance test.",
    "reference": "https://controlco.example/advisories/CTRL-2026-11",
    "fixed_versions": ["3.9.0"]
  },
  "manifest": {
    "manifest_id": "MAN-0412",
    "machine": { "manufacturer": "Grimaldi", "model": "AR-7", "serial": "0412", "site": "Plant 2, Line 4" },
    "source": "as_found",
    "taken_at": "2026-09-01T00:00:00Z",
    "taken_by": { "identifier": "a.integrator", "role": "safety engineer" },
    "items": [
      {
        "item_id": "ITM-FW",
        "kind": "firmware",
        "name": "Safety controller firmware",
        "version": "3.8.2",
        "content_hash": "1111111111111111111111111111111111111111111111111111111111111111",
        "hash_source": "read_from_machine",
        "supplier": "ControlCo",
        "implements": ["SF-01", "SF-02"]
      }
    ],
    "functions": [
      { "function_id": "SF-01", "description": "Protective stop on zone intrusion", "required_performance": "PL d", "verified_by": ["ssm_separation", "stop_characterisation"] },
      { "function_id": "SF-02", "description": "Speed limit in collaborative operation", "required_performance": "PL d", "verified_by": ["speed_limit"] }
    ],
    "method": "read via controller service port"
  }
}`;

type Match = {
  item_id: string;
  item_name: string;
  item_version: string;
  basis: string;
  confidence: string;
  needs_a_human: boolean;
  detail: string;
  implements: string[];
};

type Verdict =
  | 'no_impact_found'
  | 'potentially_affected'
  | 'requires_reverification'
  | 'requires_human_review'
  | 'insufficient_evidence'
  | 'cannot_determine'
  | 'verified';

type CheckResponse = {
  machine: string;
  verdict: Verdict;
  enrolled: boolean;
  advisory_evaluated: boolean;
  affected: boolean;
  configuration: { status: 'matched' | 'changed' | 'unknown'; changes: unknown[] };
  matches: Match[];
  evidence: { valid: number; stale: number; insufficient: number; cannot_determine: number };
  required_actions: string[];
  human_review_required: boolean;
  checks_skipped: string[];
  commercial_next_action: { action: string; endpoint: string | null };
};

const NEXT_ACTION_LABEL: Record<string, string> = {
  enroll_machine: 'Enroll this machine to unlock evidence-staleness checks and the fleet fan-out.',
  verify_machine: 'Run machine safety verification to close this gap.',
  generate_report: 'Generate the fleet report for this finding.',
  contact_sales: 'This needs a human to look — talk to sales.',
  provide_more_evidence: 'Declare the missing checks or hashes and re-run the check.',
  none: 'Nothing further to buy for this result.',
};

const NEXT_ACTION_HREF: Record<string, string> = {
  enroll_machine: '/investigate',
  verify_machine: '/investigate',
  generate_report: '/investigate',
  contact_sales: '/contact',
};

const NEXT_ACTION_CTA: Record<string, string> = {
  enroll_machine: 'Go to Investigate',
  verify_machine: 'Go to Investigate',
  generate_report: 'Go to Investigate',
  contact_sales: 'Contact sales',
};

const VERDICT_LABEL: Record<Verdict, string> = {
  no_impact_found: 'NO IMPACT FOUND',
  potentially_affected: 'POTENTIALLY AFFECTED',
  requires_reverification: 'REQUIRES RE-VERIFICATION',
  requires_human_review: 'REQUIRES HUMAN REVIEW',
  insufficient_evidence: 'INSUFFICIENT EVIDENCE',
  cannot_determine: 'CANNOT DETERMINE',
  verified: 'VERIFIED',
};

const VERDICT_CLASS: Record<Verdict, string> = {
  no_impact_found: 'ok',
  verified: 'ok',
  potentially_affected: 'blocked',
  requires_reverification: 'blocked',
  requires_human_review: 'blocked',
  insufficient_evidence: 'blocked',
  cannot_determine: 'blocked',
};

export default function AdvisoryCheckPlayground() {
  const [input, setInput] = useState(SAMPLE_PAYLOAD);
  const [result, setResult] = useState<CheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setError(null);
    setResult(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(input);
    } catch {
      setError('That is not valid JSON — fix the syntax and try again.');
      return;
    }
    if (!API_BASE) {
      setError(
        'Not deployed publicly yet — this button has nowhere to send the request. Run it yourself: ' +
          "pip install -e '.[assurance-api]' && uvicorn assurance.api.service:app, then POST this JSON to /v1/check/machine.",
      );
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/v1/check/machine`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(parsed),
      });
      const body = await res.json().catch(() => null);
      if (!res.ok) {
        const message =
          typeof body?.detail === 'string' ? body.detail : body?.detail?.detail || `The service answered ${res.status}. This is the real error, not a mockup.`;
        setError(message);
        setLoading(false);
        return;
      }
      setResult(body as CheckResponse);
    } catch {
      setError('Could not reach the API host. It may not be deployed, or your network blocked the request.');
    }
    setLoading(false);
  };

  return (
    <div className="playground">
      <div className="playground-grid">
        <div className="playground-input">
          <label htmlFor="advisory-json" className="playground-label">
            POST /v1/check/machine — edit the advisory or the manifest
          </label>
          <textarea
            id="advisory-json"
            className="playground-textarea"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            spellCheck={false}
            rows={16}
          />
          <button className="btn btn-primary" onClick={run} disabled={loading}>
            {loading ? 'Checking…' : 'Run the Machine Assurance Check'}
          </button>
        </div>

        <div className="playground-output">
          <span className="playground-label">Result</span>
          {!result && !error && (
            <p className="playground-placeholder">
              {API_BASE
                ? 'One advisory against one machine’s manifest — free, no account. Edit either and click Run.'
                : 'This endpoint is not hosted publicly yet — click Run to see exactly what that means and how to run it yourself.'}
            </p>
          )}
          {error && <p className="playground-error">{error}</p>}
          {result && (
            <div className="playground-result">
              <span className={`playground-verdict ${VERDICT_CLASS[result.verdict]}`}>
                {VERDICT_LABEL[result.verdict]} — {result.machine}
              </span>

              {result.matches.length > 0 && (
                <ul className="playground-issues">
                  {result.matches.map((m) => (
                    <li key={m.item_id}>
                      <strong>
                        {m.item_name} {m.item_version} — [{m.confidence}]
                        {m.needs_a_human ? ' needs a human' : ''}
                      </strong>
                      <span>{m.detail}</span>
                      {m.implements.length > 0 && (
                        <span> Implements: {m.implements.join(', ')}.</span>
                      )}
                    </li>
                  ))}
                </ul>
              )}

              {result.checks_skipped.length > 0 && (
                <p style={{ fontSize: '0.78rem', color: 'var(--ink-soft)', marginTop: '0.5rem' }}>
                  {result.checks_skipped[0]}
                </p>
              )}

              <div className="ai-card" style={{ marginTop: '0.75rem' }}>
                <span className="status-pill register">Next: {result.commercial_next_action.action.replace(/_/g, ' ')}</span>
                <p style={{ fontSize: '0.85rem' }}>
                  {NEXT_ACTION_LABEL[result.commercial_next_action.action] ?? 'See pricing for what unlocks this.'}
                  {result.commercial_next_action.endpoint && (
                    <>
                      {' '}This calls <code>{result.commercial_next_action.endpoint}</code> — see the full catalogue
                      at <code>GET /v1/check/services</code>.
                    </>
                  )}
                </p>
                <a className="btn btn-primary" href={NEXT_ACTION_HREF[result.commercial_next_action.action] ?? '/#pricing'}>
                  {NEXT_ACTION_CTA[result.commercial_next_action.action] ?? 'See pricing'}
                </a>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
