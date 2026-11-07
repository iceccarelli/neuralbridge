'use client';

import RepoLink from './RepoLink';
import { useEffect, useRef, useState } from 'react';
import { useSharedApiKey } from '../lib/apiKey';
import { AI_ACTOR_STORAGE as ACTOR_STORAGE, AI_SESSION_STORAGE as SESSION_STORAGE, CREDENTIALS_CLEARED_EVENT } from '../lib/credentials';
import AdaptersPanel from './ai/AdaptersPanel';
import AuditPanel from './ai/AuditPanel';
import ConnectionsPanel, { isDemoSource } from './ai/ConnectionsPanel';
import JourneyNav from './assurance/JourneyNav';
import WorkspaceHeader, { DemoLabel, PLATFORM_ORIGIN } from './assurance/WorkspaceHeader';

const API_BASE = process.env.NEXT_PUBLIC_NEURALBRIDGE_API_URL || '';

type Connection = { id: string; name: string; adapter_type: string; status: string; source: string };
type Capability = { operation: string; operation_class: 'read' | 'write' | 'destructive'; description: string };
type Provenance = {
  connection_id: string;
  connection_name: string;
  adapter_type: string;
  tool: string;
  request_id: string;
  timestamp: string;
  mocked: boolean;
};
type QueryResultCard = { success: boolean; data: unknown; error: string | null; provenance: Provenance };
type Plan = {
  id: string;
  connection_id: string;
  operation: string;
  operation_class: string;
  params: Record<string, unknown>;
  status: string;
  deny_reason?: string | null;
};
type ApprovalCard = { plan: Plan; risk_note: string };
type ExecutionReceipt = {
  plan_id: string;
  success: boolean;
  data: unknown;
  error: string | null;
  provenance: Provenance;
  approved_by: string;
  executed_at: string;
};

type Session = { actor_id: string; session_id: string; tier: string; ai_control_plane: boolean; ai_reads_per_day: number | null };
type UpgradeDetail = { error: string; tier: string; remedy: string };

type Turn =
  | { kind: 'user'; text: string }
  | { kind: 'agent-text'; text: string }
  | { kind: 'result'; card: QueryResultCard }
  | { kind: 'approval'; card: ApprovalCard }
  | { kind: 'receipt'; card: ExecutionReceipt }
  | { kind: 'denied'; plan: Plan }
  | { kind: 'upgrade'; detail: UpgradeDetail; retry?: { connection_id: string; operation: string; params: Record<string, unknown> } }
  | { kind: 'error'; text: string };

function useSessionIdentity() {
  const [actorId, setActorId] = useState('');
  const [sessionId, setSessionId] = useState('');

  useEffect(() => {
    const init = () => {
    try {
      let a = window.sessionStorage.getItem(ACTOR_STORAGE);
      let s = window.sessionStorage.getItem(SESSION_STORAGE);
      if (!a) {
        a = `operator-${Math.random().toString(36).slice(2, 8)}`;
        window.sessionStorage.setItem(ACTOR_STORAGE, a);
      }
      if (!s) {
        s = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}`;
        window.sessionStorage.setItem(SESSION_STORAGE, s);
      }
      setActorId(a);
      setSessionId(s);
    } catch {
      setActorId('operator-local');
      setSessionId('local-session');
    }
    };
    init();
    // After sign-out the stored identifiers are gone: start a fresh, unlinked session.
    window.addEventListener(CREDENTIALS_CLEARED_EVENT, init);
    return () => window.removeEventListener(CREDENTIALS_CLEARED_EVENT, init);
  }, []);

  return { actorId, sessionId, setActorId };
}

// A deterministic capability router, not an LLM call — this repo's own
// product law is that the model is never the system of record, and this
// slice ships without external LLM credentials by design. Every fact shown
// still comes from a real RequestRouter call; this only decides *which*
// call your message maps to.
function parseIntent(
  text: string,
  capabilities: Capability[]
): { kind: 'read' | 'plan'; operation: string; params: Record<string, unknown> } | { kind: 'help' } | { kind: 'unrecognized' } {
  const t = text.trim();
  const lower = t.toLowerCase();

  if (!t) return { kind: 'unrecognized' };
  if (/^(help|what can i do|capabilities)\??$/.test(lower)) return { kind: 'help' };
  if (/^(health ?check|check connection|are you (there|connected))\??$/.test(lower)) {
    return { kind: 'read', operation: 'health_check', params: {} };
  }
  if (/^list tables\??$/.test(lower)) return { kind: 'read', operation: 'list_tables', params: {} };

  const describeMatch = lower.match(/^describe (?:table )?([a-z0-9_]+)$/);
  if (describeMatch) return { kind: 'read', operation: 'describe_table', params: { table_name: describeMatch[1] } };

  if (/^select\b/i.test(t)) return { kind: 'read', operation: 'query', params: { sql: t } };

  if (/^(update|insert|delete|drop|create|alter|truncate)\b/i.test(t)) {
    const known = capabilities.some((c) => c.operation === 'execute_sql');
    if (known) return { kind: 'plan', operation: 'execute_sql', params: { sql: t } };
  }

  return { kind: 'unrecognized' };
}

async function apiFetch(path: string, opts: RequestInit, actorId: string, sessionId: string, apiKey?: string) {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'X-NB-Actor': actorId,
    'X-NB-Session': sessionId,
    ...(apiKey ? { 'X-API-Key': apiKey } : {}),
    ...((opts.headers as Record<string, string>) || {}),
  };
  const res = await fetch(`${API_BASE}${path}`, { ...opts, headers });
  const body = await res.json().catch(() => null);
  return { status: res.status, body };
}

function isUpgradeDetail(detail: unknown): detail is UpgradeDetail {
  return (
    typeof detail === 'object' &&
    detail !== null &&
    'error' in detail &&
    (detail as { error?: unknown }).error === 'plan_does_not_include_ai_control_plane'
  );
}

function ProvenanceLine({ p }: { p: Provenance }) {
  return (
    <div className="ai-provenance">
      {p.connection_name} · {p.tool} · {new Date(p.timestamp).toLocaleTimeString()} · req {p.request_id.slice(0, 8)}
      {p.mocked && (
        <>
          {' '}
          · <strong style={{ color: 'var(--danger)' }}>MOCK DATA — adapter is not actually connected</strong>
        </>
      )}
    </div>
  );
}

export default function AiWorkspace() {
  const { actorId, sessionId, setActorId } = useSessionIdentity();
  const { key: apiKey, setKey: setApiKey } = useSharedApiKey();
  const [connections, setConnections] = useState<Connection[]>([]);
  const [selected, setSelected] = useState<Connection | null>(null);
  const [capabilities, setCapabilities] = useState<Capability[]>([]);
  const [session, setSession] = useState<Session | null>(null);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [connError, setConnError] = useState<string | null>(null);
  const [connLoading, setConnLoading] = useState(false);
  const [sessionState, setSessionState] = useState<{ loaded: boolean; failed: string | null }>({ loaded: false, failed: null });
  const [refreshTick, setRefreshTick] = useState(0);
  const [lastAudit, setLastAudit] = useState<{ event_type: string; action: string; result: string; timestamp: string }[]>([]);
  const logRef = useRef<HTMLDivElement>(null);

  // Sign-out: drop everything held for the old key, not just the key itself.
  useEffect(() => {
    const drop = () => {
      setSession(null);
      setSessionState({ loaded: false, failed: null });
      setConnections([]);
      setSelected(null);
      setCapabilities([]);
      setTurns([]);
      setLastAudit([]);
      setConnError(null);
      setInput('');
    };
    window.addEventListener(CREDENTIALS_CLEARED_EVENT, drop);
    return () => window.removeEventListener(CREDENTIALS_CLEARED_EVENT, drop);
  }, []);

  // What a refusal means, in words: a 401 is a key problem, a 402 a plan one, anything else is the
  // API's own state. Never "could not reach" for an answer that did arrive.
  const refusalText = (status: number, body: unknown, what: string): string => {
    const detail = (body as { detail?: unknown } | null)?.detail;
    const text =
      typeof detail === 'string'
        ? detail
        : detail && typeof detail === 'object' && typeof (detail as { remedy?: unknown }).remedy === 'string'
          ? (detail as { remedy: string }).remedy
          : '';
    if (status === 401) return `${what}: the API did not accept this key (HTTP 401). ${text}`.trim();
    if (status === 402) return `${what}: not included in your plan (HTTP 402). ${text}`.trim();
    if (status === 403) return `${what}: refused (HTTP 403). ${text}`.trim();
    return `${what}: the API answered HTTP ${status}. ${text}`.trim();
  };

  useEffect(() => {
    if (!actorId || !API_BASE) return;
    let live = true;
    setSessionState({ loaded: false, failed: null });
    apiFetch('/ai/session', { method: 'GET' }, actorId, sessionId, apiKey)
      .then(({ status, body }) => {
        if (!live) return;
        if (status === 200) {
          setSession(body as Session);
          setSessionState({ loaded: true, failed: null });
        } else {
          setSession(null);
          setSessionState({ loaded: false, failed: refusalText(status, body, 'Plan') });
        }
      })
      .catch(() => {
        if (!live) return;
        setSession(null);
        setSessionState({ loaded: false, failed: 'Plan: the API could not be reached from this browser.' });
      });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [actorId, sessionId, apiKey]);

  useEffect(() => {
    if (!actorId || !API_BASE) return;
    let live = true;
    setConnLoading(true);
    apiFetch('/ai/connections', { method: 'GET' }, actorId, sessionId, apiKey)
      .then(({ status, body }) => {
        if (!live) return;
        setConnLoading(false);
        if (status !== 200) {
          setConnections([]);
          setSelected(null);
          setConnError(refusalText(status, body, 'Data sources') + ' See docs/ai-local-setup.md.');
          return;
        }
        const list = body as Connection[];
        setConnections(list);
        setSelected((prev) => list.find((c) => c.id === prev?.id) || list[0] || null);
        setConnError(list.length > 0 ? null : 'No connections configured — set NEURALBRIDGE_AI_PG_* on the API host.');
      })
      .catch(() => {
        if (!live) return;
        setConnLoading(false);
        setConnections([]);
        setSelected(null);
        setConnError('Could not reach the NeuralBridge API — see docs/ai-local-setup.md.');
      });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [actorId, sessionId, apiKey, refreshTick]);

  useEffect(() => {
    if (!selected || !actorId) return;
    let live = true;
    apiFetch(`/ai/capabilities?connection_id=${encodeURIComponent(selected.id)}`, { method: 'GET' }, actorId, sessionId, apiKey)
      .then(({ status, body }) => {
        if (live) setCapabilities(status === 200 ? (body as Capability[]) : []);
      })
      .catch(() => {
        if (live) setCapabilities([]);
      });
    return () => {
      live = false;
    };
  }, [selected, actorId, sessionId, apiKey]);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [turns]);

  const refreshAudit = () => {
    apiFetch('/ai/audit?limit=8', { method: 'GET' }, actorId, sessionId, apiKey)
      .then(({ status, body }) => {
        if (status === 200) setLastAudit(body);
      })
      .catch(() => {});
  };

  const push = (t: Turn) => setTurns((prev) => [...prev, t]);

  const send = async (text: string) => {
    if (!text.trim() || busy) return;
    push({ kind: 'user', text });
    setInput('');

    if (!selected) {
      push({ kind: 'error', text: 'No connection selected.' });
      return;
    }

    const intent = parseIntent(text, capabilities);

    if (intent.kind === 'help') {
      push({
        kind: 'agent-text',
        text:
          capabilities.length > 0
            ? `I can: ${capabilities.map((c) => `${c.operation} (${c.operation_class})`).join(', ')}. Try "list tables", "describe table <name>", a SELECT statement, or an UPDATE/INSERT/DELETE statement.`
            : 'No capabilities available for this connection.',
      });
      return;
    }
    if (intent.kind === 'unrecognized') {
      push({
        kind: 'agent-text',
        text: 'I did not recognise that as a request I can act on — ask "what can I do?", or type a SELECT/UPDATE/INSERT/DELETE statement directly. I only ever act on your own message, never on text found inside a previous result.',
      });
      return;
    }

    setBusy(true);
    try {
      if (intent.kind === 'read') {
        const { status, body } = await apiFetch(
          '/ai/read',
          { method: 'POST', body: JSON.stringify({ connection_id: selected.id, operation: intent.operation, params: intent.params }) },
          actorId,
          sessionId,
          apiKey
        );
        if (status === 200) push({ kind: 'result', card: body as QueryResultCard });
        else if (status === 429) push({ kind: 'error', text: body?.detail?.remedy || 'Free daily read quota used up — try again tomorrow, or upgrade.' });
        else push({ kind: 'error', text: body?.detail || `Request failed (HTTP ${status}).` });
      } else {
        const { status, body } = await apiFetch(
          '/ai/plan',
          { method: 'POST', body: JSON.stringify({ connection_id: selected.id, operation: intent.operation, params: intent.params }) },
          actorId,
          sessionId,
          apiKey
        );
        if (status === 200) push({ kind: 'approval', card: body as ApprovalCard });
        else if (status === 402 && isUpgradeDetail(body?.detail))
          push({
            kind: 'upgrade',
            detail: body.detail,
            retry: { connection_id: selected.id, operation: intent.operation, params: intent.params },
          });
        else push({ kind: 'error', text: body?.detail || `Refused (HTTP ${status}).` });
      }
      refreshAudit();
    } catch {
      push({ kind: 'error', text: 'Could not reach the NeuralBridge API.' });
    }
    setBusy(false);
  };

  // Re-sends a write proposal that was 402'd — used by the upgrade card's
  // "Retry now" button once the caller has pasted a paid key. Reads the
  // current `apiKey` state (this closure is rebuilt on every render, so a
  // key pasted after the 402 is picked up with no page reload), so the
  // caller never has to retype the request that got blocked.
  const retryWrite = async (payload: { connection_id: string; operation: string; params: Record<string, unknown> }) => {
    setBusy(true);
    try {
      const { status, body } = await apiFetch(
        '/ai/plan',
        { method: 'POST', body: JSON.stringify(payload) },
        actorId,
        sessionId,
        apiKey
      );
      if (status === 200) push({ kind: 'approval', card: body as ApprovalCard });
      else if (status === 402 && isUpgradeDetail(body?.detail)) push({ kind: 'upgrade', detail: body.detail, retry: payload });
      else push({ kind: 'error', text: body?.detail || `Refused (HTTP ${status}).` });
      refreshAudit();
    } catch {
      push({ kind: 'error', text: 'Could not reach the NeuralBridge API.' });
    }
    setBusy(false);
  };

  const decide = async (planId: string, approve: boolean) => {
    setBusy(true);
    try {
      if (approve) {
        const { status, body } = await apiFetch(`/ai/plan/${planId}/approve`, { method: 'POST' }, actorId, sessionId, apiKey);
        if (status === 200) push({ kind: 'receipt', card: body as ExecutionReceipt });
        else if (status === 402 && isUpgradeDetail(body?.detail)) push({ kind: 'upgrade', detail: body.detail });
        else push({ kind: 'error', text: body?.detail || `Approval failed (HTTP ${status}).` });
      } else {
        const { status, body } = await apiFetch(
          `/ai/plan/${planId}/deny?reason=${encodeURIComponent('denied by operator in /ai')}`,
          { method: 'POST' },
          actorId,
          sessionId,
          apiKey
        );
        if (status === 200) push({ kind: 'denied', plan: body as Plan });
        else push({ kind: 'error', text: body?.detail || `Deny failed (HTTP ${status}).` });
      }
      refreshAudit();
    } catch {
      push({ kind: 'error', text: 'Could not reach the NeuralBridge API.' });
    }
    setBusy(false);
  };

  if (!API_BASE) {
    return (
      <>
      <WorkspaceHeader surface="ai" origin={PLATFORM_ORIGIN} apiKey={apiKey} />
      <p className="ai-banner">
        This panel is honestly disabled, not faking a response: this deployment has no{' '}
        <code>NEXT_PUBLIC_NEURALBRIDGE_API_URL</code> set. Run the platform API yourself —{' '}
        <code>uvicorn neuralbridge.main:app --factory</code> — and point <code>NEXT_PUBLIC_NEURALBRIDGE_API_URL</code>{' '}
        at it. See{' '}
        <RepoLink path="/blob/main/docs/ai-local-setup.md" plain>docs/ai-local-setup.md</RepoLink>.
      </p>
      </>
    );
  }

  return (
    <div className="ai-shell">
      <div className="key-row">
        <label htmlFor="ai-api-key">API key (optional — required for writes)</label>
        <input
          id="ai-api-key"
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder="paste your X-API-Key — Register/Cell"
          autoComplete="off"
        />
        <span className="key-row-note">Kept in this tab's sessionStorage only — never sent anywhere but the API below, never persisted after you close the tab.</span>
      </div>

      <WorkspaceHeader
        surface="ai"
        origin={PLATFORM_ORIGIN}
        apiKey={apiKey}
        platformSession={{ tier: session?.tier ?? '', loaded: sessionState.loaded, failed: sessionState.failed }}
      />
      <JourneyNav />

      {connLoading && connections.length === 0 && (
        <p className="console-empty-note" role="status">
          Loading your data sources…
        </p>
      )}
      {connError && (
        <p className="ai-banner" role="alert">
          {connError}
        </p>
      )}

      <div className="ai-grid">
        <div className="ai-pane">
          <h2>Conversation</h2>
          {selected && isDemoSource(selected) && (
            <p data-testid="demo-banner">
              <DemoLabel>Demonstration data</DemoLabel>{' '}
              <span style={{ fontSize: '0.82rem' }}>
                This is the shared demo database (not your records, and not a machine of yours). Anything you read here
                describes the demo only.
              </span>
            </p>
          )}
          <div className="ai-log" ref={logRef}>
            {turns.length === 0 && (
              <p style={{ color: 'var(--ink-soft)', fontSize: '0.88rem' }}>
                Try &ldquo;what can I do?&rdquo;, &ldquo;list tables&rdquo;, a SELECT statement, or an UPDATE — writes
                always stop for your approval.
              </p>
            )}
            {turns.map((turn, i) => (
              <TurnView
                key={i}
                turn={turn}
                onDecide={decide}
                onRetryWrite={retryWrite}
                busy={busy}
                hasApiKey={!!apiKey}
                demoIds={connections.filter(isDemoSource).map((c) => c.id)}
              />
            ))}
          </div>
          <div className="ai-suggestions">
            {['what can I do?', 'list tables', 'SELECT * FROM demo_customers'].map((s) => (
              <button key={s} type="button" className="ai-suggestion" onClick={() => send(s)} disabled={busy}>
                {s}
              </button>
            ))}
          </div>
          <div className="ai-input-row">
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') send(input);
              }}
              placeholder="Ask, or type SQL…"
              disabled={busy || !selected}
              aria-label="Message"
            />
            <button className="btn btn-primary" onClick={() => send(input)} disabled={busy || !selected}>
              {busy ? '…' : 'Send'}
            </button>
          </div>
        </div>

        <div className="ai-pane">
          <h2>Context</h2>
          <div>
            {session && (
              <div className="ai-context-row">
                <span>Plan</span>
                <span>
                  <span className={`status-pill ai-plan-pill ${session.tier}`}>{session.tier}</span>{' '}
                  {session.ai_control_plane
                    ? 'control plane: full'
                    : `reads: ${session.ai_reads_per_day ?? '∞'}/day, writes need upgrade`}
                </span>
              </div>
            )}
            {!session?.ai_control_plane && (
              <p className="ai-upgrade-hint">
                On the free Validator plan: reads work, writes need <a href="/#pricing">Register or Cell</a>. Already
                have a key? Paste it above, or open your first case in{' '}
                <a href="/console#first-case">the Console&apos;s guided flow</a> — a key pasted there shows up here
                too, same browser tab. See <a href="/#pricing">pricing</a> or the{' '}
                <a href="/connectors/mcp">connectors</a> for other ways in.
              </p>
            )}
            <div className="ai-context-row">
              <span>Actor</span>
              <span>
                <input
                  style={{ width: '10rem', fontSize: '0.8rem', textAlign: 'right', border: 'none', background: 'transparent' }}
                  value={actorId}
                  onChange={(e) => setActorId(e.target.value)}
                  aria-label="Actor id"
                />
              </span>
            </div>
            <div className="ai-context-row">
              <span>Session</span>
              <span style={{ fontFamily: 'monospace', fontSize: '0.76rem' }}>{sessionId.slice(0, 8)}</span>
            </div>
            <div className="ai-context-row">
              <span>Connection</span>
              <span>
                <select
                  value={selected?.id || ''}
                  onChange={(e) => setSelected(connections.find((c) => c.id === e.target.value) || null)}
                  aria-label="Connection"
                >
                  {connections.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name}
                    </option>
                  ))}
                </select>
              </span>
            </div>
            {selected && (
              <>
                <div className="ai-context-row">
                  <span>Adapter</span>
                  <span>{selected.adapter_type}</span>
                </div>
                <div className="ai-context-row">
                  <span>Source</span>
                  <span>{selected.source === 'seeded_from_env' ? 'seeded from env — not a real Connection Wizard entry' : 'connections API'}</span>
                </div>
              </>
            )}
          </div>

          <h2>Permissions</h2>
          <div>
            {capabilities.length === 0 && <p style={{ fontSize: '0.82rem', color: 'var(--ink-soft)' }}>No connection selected.</p>}
            {capabilities.map((c) => (
              <div className="ai-context-row" key={c.operation}>
                <span>{c.operation}</span>
                <span className={`status-pill ${c.operation_class === 'read' ? 'free' : 'cell'}`}>{c.operation_class}</span>
              </div>
            ))}
          </div>

          <h2>Last audit events</h2>
          <button className="ai-suggestion" type="button" onClick={refreshAudit} style={{ alignSelf: 'flex-start' }}>
            Refresh
          </button>
          <div>
            {lastAudit.length === 0 && <p style={{ fontSize: '0.82rem', color: 'var(--ink-soft)' }}>None yet this session.</p>}
            {lastAudit.map((e, i) => (
              <div className="ai-context-row" key={i}>
                <span>
                  {e.action} · {e.result}
                </span>
                <span style={{ fontSize: '0.74rem' }}>{new Date(e.timestamp).toLocaleTimeString()}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <AdaptersPanel apiKey={apiKey} />
      <ConnectionsPanel apiKey={apiKey} sources={connections} onChanged={() => setRefreshTick((n) => n + 1)} />
      <AuditPanel apiKey={apiKey} />
    </div>
  );
}

function TurnView({
  turn,
  onDecide,
  onRetryWrite,
  busy,
  hasApiKey,
  demoIds,
}: {
  turn: Turn;
  demoIds: string[];
  onDecide: (id: string, approve: boolean) => void;
  onRetryWrite: (payload: { connection_id: string; operation: string; params: Record<string, unknown> }) => void;
  busy: boolean;
  hasApiKey: boolean;
}) {
  if (turn.kind === 'user') return <div className="ai-turn user">{turn.text}</div>;
  if (turn.kind === 'agent-text') return <div className="ai-turn agent">{turn.text}</div>;
  if (turn.kind === 'error')
    return (
      <div className="ai-turn agent">
        <span className="playground-verdict blocked">Error</span> {turn.text}
      </div>
    );

  if (turn.kind === 'result') {
    const { card } = turn;
    return (
      <div className="ai-card">
        <div className="ai-card-title">
          <span className={`playground-verdict ${card.success ? 'ok' : 'blocked'}`}>{card.success ? 'Read OK' : 'Read failed'}</span>{' '}
          {demoIds.includes(card.provenance.connection_id) && <DemoLabel>Demonstration data</DemoLabel>}
        </div>
        {card.error && <p style={{ color: 'var(--danger)', fontSize: '0.85rem' }}>{card.error}</p>}
        {card.data !== null && card.data !== undefined && <pre className="code-panel">{JSON.stringify(card.data, null, 2)}</pre>}
        <ProvenanceLine p={card.provenance} />
      </div>
    );
  }

  if (turn.kind === 'approval') {
    const { plan, risk_note } = turn.card;
    const decided = plan.status !== 'pending_approval';
    return (
      <div className="ai-card">
        <div className="ai-card-title">
          <span className="status-pill cell">{plan.operation_class.toUpperCase()} — approval required</span>
        </div>
        <pre className="code-panel">{JSON.stringify(plan.params, null, 2)}</pre>
        <p style={{ fontSize: '0.85rem' }}>{risk_note}</p>
        {!decided && (
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className="btn btn-primary" disabled={busy} onClick={() => onDecide(plan.id, true)}>
              Approve &amp; execute
            </button>
            <button className="btn btn-secondary" disabled={busy} onClick={() => onDecide(plan.id, false)}>
              Deny
            </button>
          </div>
        )}
      </div>
    );
  }

  if (turn.kind === 'receipt') {
    const { card } = turn;
    return (
      <div className="ai-card">
        <div className="ai-card-title">
          <span className={`playground-verdict ${card.success ? 'ok' : 'blocked'}`}>Execution receipt</span>{' '}
          {demoIds.includes(card.provenance.connection_id) && <DemoLabel>Demonstration data</DemoLabel>}
        </div>
        {card.data !== null && card.data !== undefined && <pre className="code-panel">{JSON.stringify(card.data, null, 2)}</pre>}
        <p style={{ fontSize: '0.8rem' }}>Approved by {card.approved_by}</p>
        <ProvenanceLine p={card.provenance} />
      </div>
    );
  }

  if (turn.kind === 'denied') {
    return (
      <div className="ai-card">
        <span className="playground-verdict blocked">Denied — nothing executed</span>
        <p style={{ fontSize: '0.82rem' }}>{turn.plan.deny_reason}</p>
      </div>
    );
  }

  if (turn.kind === 'upgrade') {
    const { detail, retry } = turn;
    return (
      <div className="ai-card ai-upgrade-card">
        <div className="ai-card-title">
          <span className="status-pill register">Register or Cell required</span>
        </div>
        <p style={{ fontSize: '0.85rem' }}>{detail.remedy}</p>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <a className="btn btn-primary" href="/#pricing">
            See pricing
          </a>
          <a className="btn btn-secondary" href="/#pricing">
            Talk to sales
          </a>
          {retry && (
            <button
              className="btn"
              disabled={busy || !hasApiKey}
              onClick={() => onRetryWrite(retry)}
              title={hasApiKey ? 'Re-send this exact write with the key you pasted' : 'Paste an API key above first'}
            >
              Retry now with your key
            </button>
          )}
        </div>
        <p style={{ fontSize: '0.74rem', color: 'var(--ink-soft)' }}>
          Not a live checkout in this message — no charge happens here. This links to the real pricing section.
          {retry
            ? ' Once you have a Register/Cell key, paste it into the "API key" field above — "Retry now" re-sends this exact write with no page reload and no retyping.'
            : ' The write itself stays exactly as proposed until you approve it after upgrading — its Approve button above is still live.'}
        </p>
      </div>
    );
  }

  return null;
}
