'use client';

import { useState } from 'react';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

const SAMPLE_PAYLOAD = `{
  "track": "actively_exploited_vulnerability",
  "stage": "early_warning",
  "payload": {
    "product_name": "AR-7 Palletising Cell",
    "member_states_available": ["DE", "CH"]
  }
}`;

type ValidateIssue = { field_number: string; field_name: string; severity: string; message: string };
type ValidateResponse = {
  submittable: boolean;
  issues: ValidateIssue[];
  checks_skipped?: string[];
};

export default function ValidatorPlayground() {
  const [input, setInput] = useState(SAMPLE_PAYLOAD);
  const [result, setResult] = useState<ValidateResponse | null>(null);
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
          "pip install -e '.[assurance-api]' && uvicorn assurance.api.service:app, then POST this JSON to /v1/spec/validate.",
      );
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/v1/spec/validate`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(parsed),
      });
      if (!res.ok) {
        setError(`The service answered ${res.status}. This is the real error, not a mockup.`);
        setLoading(false);
        return;
      }
      const data = (await res.json()) as ValidateResponse;
      setResult(data);
    } catch {
      setError('Could not reach the API host. It may not be deployed, or your network blocked the request.');
    }
    setLoading(false);
  };

  return (
    <div className="playground">
      <div className="playground-grid">
        <div className="playground-input">
          <label htmlFor="validator-json" className="playground-label">
            POST /v1/spec/validate — edit the payload
          </label>
          <textarea
            id="validator-json"
            className="playground-textarea"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            spellCheck={false}
            rows={10}
          />
          <button className="btn btn-primary" onClick={run} disabled={loading}>
            {loading ? 'Validating…' : 'Validate'}
          </button>
        </div>

        <div className="playground-output">
          <span className="playground-label">Response</span>
          {!result && !error && (
            <p className="playground-placeholder">
              {API_BASE
                ? 'Edit the payload and click Validate to call the live free endpoint.'
                : 'This endpoint is not hosted publicly yet — click Validate to see exactly what that means and how to run it yourself.'}
            </p>
          )}
          {error && <p className="playground-error">{error}</p>}
          {result && (
            <div className="playground-result">
              <span className={`playground-verdict ${result.submittable ? 'ok' : 'blocked'}`}>
                {result.submittable ? 'Submittable' : 'Not submittable'}
              </span>
              {result.issues.length > 0 && (
                <ul className="playground-issues">
                  {result.issues.map((issue) => (
                    <li key={issue.field_number + issue.field_name}>
                      <strong>Field {issue.field_number} — {issue.field_name}</strong>
                      <span>{issue.message}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
