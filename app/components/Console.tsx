'use client';

import { useState } from 'react';
import { ROUTES, TIER_LABEL, type RouteRow } from '../lib/routes';
import { useSharedApiKey } from '../lib/apiKey';
import FirstCase from './FirstCase';
import FirstCell from './FirstCell';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

// A browser REST console, not a shell. It only ever does two things: read an
// API key from this tab's sessionStorage (shared with /ai — see
// ../lib/apiKey — never sent anywhere but the configured API_BASE, never
// persisted past the tab closing), and call the real /v1 routes over
// fetch(). No websocket, no PTY, no server-side process — there is nothing
// here to sandbox because nothing here executes arbitrary commands.

export default function Console() {
  const { key: apiKey, setKey: setApiKey } = useSharedApiKey();
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<RouteRow>(ROUTES[0]);
  const [body, setBody] = useState('{}');
  const [response, setResponse] = useState<{ status: number; text: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const filtered = ROUTES.filter(
    (r) =>
      filter.trim() === '' ||
      r.path.toLowerCase().includes(filter.toLowerCase()) ||
      r.summary.toLowerCase().includes(filter.toLowerCase())
  );

  const run = async () => {
    setError(null);
    setResponse(null);
    if (!API_BASE) {
      setError('No API URL configured for this deployment — see /status for what to set.');
      return;
    }
    setLoading(true);
    try {
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (apiKey) headers['X-API-Key'] = apiKey;
      const init: RequestInit = { method: selected.method, headers };
      if (selected.method !== 'GET') init.body = body;
      const res = await fetch(`${API_BASE}${selected.path.replace(/\{[^}]+\}/g, '1')}`, init);
      const text = await res.text();
      setResponse({ status: res.status, text });
    } catch {
      setError('Could not reach the API host — it may be down, or your network blocked the request.');
    }
    setLoading(false);
  };

  return (
    <div className="console-shell">
      <div className="key-row">
        <label htmlFor="console-api-key">API key (optional for free routes)</label>
        <input
          id="console-api-key"
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder="paste your X-API-Key"
          autoComplete="off"
        />
        <span className="key-row-note">
          Kept in this tab&apos;s sessionStorage only — never sent anywhere but the API below, never persisted after
          you close the tab. Shared with <a href="/ai">/ai</a>: paste it once, use it in either place.
        </span>
      </div>

      <FirstCase apiBase={API_BASE} apiKey={apiKey} />
      <FirstCell apiBase={API_BASE} apiKey={apiKey} />

      <div className="console-grid">
        <div className="console-routes">
          <input
            className="console-filter"
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter routes (e.g. machine, plans, attest)"
            aria-label="Filter routes"
          />
          <div className="console-route-list">
            {filtered.map((r) => (
              <button
                key={`${r.method} ${r.path}`}
                type="button"
                className={`console-route-item ${selected.path === r.path && selected.method === r.method ? 'active' : ''}`}
                onClick={() => {
                  setSelected(r);
                  setResponse(null);
                  setError(null);
                }}
              >
                <span className="console-route-method">{r.method}</span>
                <span className="console-route-path">{r.path}</span>
                <span className={`status-pill ${r.tier}`}>{TIER_LABEL[r.tier]}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="console-call">
          <p className="playground-label" style={{ color: 'var(--ink-soft)' }}>
            {selected.method} {selected.path} — {selected.summary}
          </p>
          {selected.method !== 'GET' && (
            <textarea
              className="console-body"
              value={body}
              onChange={(e) => setBody(e.target.value)}
              rows={8}
              spellCheck={false}
            />
          )}
          <button className="btn btn-primary" onClick={run} disabled={loading || !API_BASE}>
            {loading ? 'Calling…' : API_BASE ? 'Run' : 'No API URL configured'}
          </button>

          {!API_BASE && (
            <p className="console-empty-note">
              This panel is honestly disabled, not faking a response: this deployment has no{' '}
              <code>NEXT_PUBLIC_ASSURANCE_API_URL</code> set. See <a href="/status">/status</a> for the founder
              checklist, or run the API yourself — <code>uvicorn assurance.api.service:app</code> — and point{' '}
              <code>NEXT_PUBLIC_ASSURANCE_API_URL</code> at it.
            </p>
          )}
          {error && <p className="playground-error">{error}</p>}
          {response && (
            <div className="console-response">
              <span className={`playground-verdict ${response.status < 400 ? 'ok' : 'blocked'}`}>
                HTTP {response.status}
              </span>
              <pre className="code-panel">{response.text}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
