'use client';

import { useEffect, useState } from 'react';
import { ROUTES, TIER_LABEL, type RouteRow } from '../lib/routes';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';
const API_KEY_STORAGE = 'nb-console-api-key';

// A browser REST console, not a shell. It only ever does two things: read an
// API key from this tab's sessionStorage (never sent anywhere but the
// configured API_BASE, never persisted past the tab closing), and call the
// real /v1 routes over fetch(). No websocket, no PTY, no server-side
// process — there is nothing here to sandbox because nothing here executes
// arbitrary commands.
function useSessionApiKey() {
  const [key, setKey] = useState('');

  useEffect(() => {
    try {
      setKey(window.sessionStorage.getItem(API_KEY_STORAGE) || '');
    } catch {
      // sessionStorage can throw in a locked-down browser context; the
      // console still works, it just won't remember the key across a re-render.
    }
  }, []);

  const update = (value: string) => {
    setKey(value);
    try {
      if (value) window.sessionStorage.setItem(API_KEY_STORAGE, value);
      else window.sessionStorage.removeItem(API_KEY_STORAGE);
    } catch {
      // Same as above — best effort only.
    }
  };

  return { key, setKey: update };
}

export default function Console() {
  const { key: apiKey, setKey: setApiKey } = useSessionApiKey();
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
      <div className="console-key-row">
        <label htmlFor="console-api-key">API key (optional for free routes)</label>
        <input
          id="console-api-key"
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder="paste your X-API-Key"
          autoComplete="off"
        />
        <span className="console-key-note">Kept in this tab's sessionStorage only — never sent anywhere but the API below, never persisted after you close the tab.</span>
      </div>

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
