'use client';

import type { ReactNode } from 'react';
import { describeOutcome, type ApiOutcome } from '../../lib/assuranceApi';
import { agoText, API_BASE, clock, STALE_AFTER_MS, useNow, type Panel } from './usePanel';

// A refusal says which one it was (401, 402, 404, 409, 413, 422, 429, unreachable, 5xx)
// and passes the server's own remedy text through.
export function Refusal({ outcome, what }: { outcome: ApiOutcome<unknown>; what: string }) {
  if (outcome.kind === 'ok') return null;
  const d = describeOutcome(outcome);
  return (
    <div className="aw-alert" role="alert" data-outcome={d.kind}>
      <strong>
        {what}: {d.heading}.
      </strong>{' '}
      {d.text}
      {d.remedy && <span className="aw-remedy">{d.remedy}</span>}
    </div>
  );
}

// A message of the page's own (input it could not read, a name it needs). Not from the server.
export function Notice({ children }: { children: ReactNode }) {
  return (
    <div className="aw-alert" role="alert" data-outcome="local">
      {children}
    </div>
  );
}

export function Skeleton({ what }: { what: string }) {
  return (
    <div className="aw-skeleton" data-testid="panel-skeleton" aria-busy="true" role="status">
      <span className="aw-visually-hidden">Loading {what}…</span>
      <span />
      <span />
      <span />
    </div>
  );
}

// When the data this panel shows was received, and a way to fetch it again.
export function AsOf({ at, loading, onReload, what }: { at: number | null; loading: boolean; onReload: () => void; what: string }) {
  const now = useNow();
  const stale = at !== null && now - at > STALE_AFTER_MS;
  return (
    <span className="aw-asof" data-testid="panel-asof" data-stale={stale ? 'true' : 'false'}>
      {at !== null ? (
        <>
          as of {clock(at)} ({agoText(now - at)}){stale ? ' — may be out of date' : ''}
        </>
      ) : (
        'not loaded'
      )}{' '}
      <button type="button" className="aw-reload" onClick={onReload} disabled={loading} aria-label={`Reload ${what}`}>
        {loading ? 'Loading…' : 'Reload'}
      </button>
    </span>
  );
}

// One panel of the workspace: its heading, its own loading/refusal/stale state, and the
// content only when there is data. A panel that has not answered is a skeleton, never an
// empty-state sentence; a panel that failed says so and is not an empty list.
export function PanelFrame<T>({
  id,
  title,
  what,
  apiKey,
  panel,
  children,
}: {
  id: string;
  title: string;
  what: string;
  apiKey: string;
  panel: Panel<T>;
  children: (data: T) => ReactNode;
}) {
  const { outcome, good, loading, reload } = panel;
  const data = outcome?.kind === 'ok' ? outcome.data : (good?.data ?? null);
  const at = outcome?.kind === 'ok' ? outcome.at : (good?.at ?? null);

  let body: ReactNode;
  if (!API_BASE) {
    body = <Refusal outcome={{ kind: 'unconfigured' }} what={title} />;
  } else if (!apiKey) {
    body = <p className="console-empty-note">Not loaded: paste an API key above.</p>;
  } else if (outcome === null || (loading && data === null)) {
    body = <Skeleton what={what} />;
  } else {
    body = (
      <>
        {outcome.kind !== 'ok' && <Refusal outcome={outcome} what={title} />}
        {outcome.kind !== 'ok' && data !== null && at !== null && (
          <p className="aw-note">
            Showing the last data received, at {clock(at)}. It may be out of date, and the request that would refresh it
            failed.
          </p>
        )}
        {data !== null && children(data)}
      </>
    );
  }

  return (
    <section aria-labelledby={`${id}-h`} id={id}>
      <div className="aw-panel-head">
        <h2 id={`${id}-h`}>{title}</h2>
        {API_BASE && apiKey && <AsOf at={at} loading={loading} onReload={() => void reload()} what={what} />}
      </div>
      {body}
    </section>
  );
}
