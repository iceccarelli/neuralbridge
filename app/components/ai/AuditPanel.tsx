'use client';

import { useState } from 'react';
import { PanelFrame } from '../assurance/PanelFrame';
import { usePanel } from '../assurance/usePanel';
import styles from '../assurance/workspace.module.css';
import { PLATFORM_BASE } from './AdaptersPanel';

// GET /logs on the platform API (src/neuralbridge/api/routes/logs.py): the audit entries stamped with
// the caller's own account (the operator sees all). Anonymous is 401. `total` in the response is the
// number of entries in THIS page, not of the trail, so "more" is inferred only from a full page.
export type AuditEvent = {
  event_id: string;
  timestamp: string;
  event_type: string;
  actor: string;
  resource: string;
  action: string;
  result: string;
  ip_address: string | null;
  details: Record<string, unknown>;
  previous_hash?: string;
  current_hash?: string;
};
export type AuditPage = { events: AuditEvent[]; total: number; limit: number; offset: number };

const PAGE = 25;

type Filters = { event_type: string; actor: string; start_date: string; end_date: string };
const NONE: Filters = { event_type: '', actor: '', start_date: '', end_date: '' };

export function auditPath(f: Filters, offset: number, limit = PAGE): string {
  const q = new URLSearchParams();
  q.set('limit', String(limit));
  q.set('offset', String(offset));
  if (f.event_type.trim()) q.set('event_type', f.event_type.trim());
  if (f.actor.trim()) q.set('actor', f.actor.trim());
  // <input type="datetime-local"> has no zone; the API wants ISO 8601, and a zone-less value is
  // read by it as given. The browser's own zone is stated next to the field.
  if (f.start_date) q.set('start_date', f.start_date);
  if (f.end_date) q.set('end_date', f.end_date);
  return `/logs?${q.toString()}`;
}

export default function AuditPanel({ apiKey }: { apiKey: string }) {
  const [requested, setRequested] = useState(false);
  if (!requested) {
    return (
      <section id="ai-audit" aria-labelledby="ai-audit-h">
        <div className="aw-panel-head">
          <h2 id="ai-audit-h">Audit log</h2>
        </div>
        <p className="aw-note">
          Reads <code>GET /logs</code>: the audit entries stamped with your account. It needs a key, so it is read on
          request.
        </p>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => setRequested(true)}
          disabled={!apiKey}
          data-testid="audit-load"
        >
          {apiKey ? 'Load the audit log' : 'Paste a key to load the audit log'}
        </button>
      </section>
    );
  }
  return <AuditLoaded apiKey={apiKey} />;
}

function AuditLoaded({ apiKey }: { apiKey: string }) {
  const [draft, setDraft] = useState<Filters>(NONE);
  const [applied, setApplied] = useState<Filters>(NONE);
  const [offset, setOffset] = useState(0);
  const panel = usePanel<AuditPage>(apiKey, auditPath(applied, offset), PLATFORM_BASE);

  const apply = (e: React.FormEvent) => {
    e.preventDefault();
    setOffset(0);
    setApplied(draft);
  };

  return (
    <PanelFrame id="ai-audit" title="Audit log" what="the audit log" apiKey={apiKey} panel={panel} base={PLATFORM_BASE}>
      {(page) => (
        <div data-testid="audit-panel">
          <form className={styles.filters} onSubmit={apply} aria-label="Audit filters">
            <div>
              <label htmlFor="audit-f-type">Event type</label>
              <input id="audit-f-type" value={draft.event_type} onChange={(e) => setDraft({ ...draft, event_type: e.target.value })} autoComplete="off" />
            </div>
            <div>
              <label htmlFor="audit-f-actor">Actor</label>
              <input id="audit-f-actor" value={draft.actor} onChange={(e) => setDraft({ ...draft, actor: e.target.value })} autoComplete="off" />
            </div>
            <div>
              <label htmlFor="audit-f-from">From (your browser&apos;s time zone)</label>
              <input id="audit-f-from" type="datetime-local" value={draft.start_date} onChange={(e) => setDraft({ ...draft, start_date: e.target.value })} />
            </div>
            <div>
              <label htmlFor="audit-f-to">To</label>
              <input id="audit-f-to" type="datetime-local" value={draft.end_date} onChange={(e) => setDraft({ ...draft, end_date: e.target.value })} />
            </div>
            <button type="submit" className="btn btn-secondary">Apply filters</button>
          </form>

          <p className="aw-note">
            This trail lives in the API process&apos;s memory unless the operator configured otherwise: it is lost on
            restart and is not shared between workers. The hashes are shown as stored; this page does not re-verify the
            chain, so an entry here is a record, not proof of completeness.
          </p>

          {page.events.length === 0 ? (
            <p className="console-empty-note" data-testid="audit-empty">
              {offset > 0
                ? 'No entries on this page.'
                : 'No audit entries for your account match. An empty trail can also mean the API restarted since the activity.'}
            </p>
          ) : (
            <div className={styles.scroll}>
              <table className={styles.table} data-testid="audit-table">
                <caption className="aw-visually-hidden">Audit entries for your account</caption>
                <thead>
                  <tr>
                    <th scope="col">When</th>
                    <th scope="col">Event</th>
                    <th scope="col">Actor</th>
                    <th scope="col">Action on resource</th>
                    <th scope="col">Result</th>
                    <th scope="col">Hash</th>
                  </tr>
                </thead>
                <tbody>
                  {page.events.map((ev) => (
                    <tr key={ev.event_id}>
                      <td>{new Date(ev.timestamp).toLocaleString()}</td>
                      <td>{ev.event_type}</td>
                      <td>{ev.actor}</td>
                      <td>
                        {ev.action} <code>{ev.resource}</code>
                      </td>
                      <td>{ev.result}</td>
                      <td>
                        <code title={ev.current_hash}>{(ev.current_hash || '').slice(0, 10) || 'none'}</code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className={styles.filters}>
            <button type="button" className="btn btn-secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
              Previous page
            </button>
            <span className="aw-note">
              Entries {page.events.length === 0 ? offset : offset + 1}–{offset + page.events.length}
            </span>
            <button type="button" className="btn btn-secondary" disabled={page.events.length < PAGE} onClick={() => setOffset(offset + PAGE)}>
              Next page
            </button>
          </div>
        </div>
      )}
    </PanelFrame>
  );
}
