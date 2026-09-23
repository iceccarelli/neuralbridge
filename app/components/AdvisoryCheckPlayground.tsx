'use client';

import { useState } from 'react';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

// A realistic single-machine advisory check — the free, no-account route this
// whole product is built around: a supplier bulletin lands, and an integrator
// answers "is this specific unit one of them" before finishing their coffee.
// Field shapes mirror tests/test_assurance_fleet.py's fixtures exactly, so this
// payload is not a prop — it is a real ComponentAdvisory and a real
// SafetyManifest that the live service will actually parse.
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

type CheckResponse = {
  advisory_id: string;
  issued_by: string;
  severity: string;
  machine: string;
  affected: boolean;
  matches: Match[];
  remedy: string;
  checks_skipped: string[];
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
          "pip install -e '.[assurance-api]' && uvicorn assurance.api.service:app, then POST this JSON to /v1/fleet/advisory/check.",
      );
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/v1/fleet/advisory/check`, {
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
            POST /v1/fleet/advisory/check — edit the advisory or the manifest
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
            {loading ? 'Checking…' : 'Run the check'}
          </button>
        </div>

        <div className="playground-output">
          <span className="playground-label">Response</span>
          {!result && !error && (
            <p className="playground-placeholder">
              {API_BASE
                ? 'This is one supplier advisory against one machine’s manifest — free, no account. Edit either and click Run.'
                : 'This endpoint is not hosted publicly yet — click Run to see exactly what that means and how to run it yourself.'}
            </p>
          )}
          {error && <p className="playground-error">{error}</p>}
          {result && (
            <div className="playground-result">
              <span className={`playground-verdict ${result.affected ? 'blocked' : 'ok'}`}>
                {result.affected ? `AFFECTED — ${result.machine}` : `CLEAR — ${result.machine}`}
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
              {result.remedy && (
                <p style={{ fontSize: '0.85rem', marginTop: '0.5rem' }}>
                  <strong>Remedy:</strong> {result.remedy}
                </p>
              )}
              {result.checks_skipped.length > 0 && (
                <p style={{ fontSize: '0.78rem', color: 'var(--ink-soft)', marginTop: '0.5rem' }}>
                  {result.checks_skipped[0]}
                </p>
              )}
              <p style={{ fontSize: '0.85rem', marginTop: '0.75rem' }}>
                This checked one machine. The Cell plan fans one advisory out across your whole enrolled fleet, all
                the way to which safety functions&apos; standing evidence it puts in question — see{' '}
                <a href="/#pricing">pricing</a>.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
