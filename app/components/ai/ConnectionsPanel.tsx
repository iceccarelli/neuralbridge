'use client';

import { useState } from 'react';
import { call, type ApiOutcome } from '../../lib/assuranceApi';
import { Notice, Refusal } from '../assurance/PanelFrame';
import styles from '../assurance/workspace.module.css';
import { DemoLabel } from '../assurance/WorkspaceHeader';
import { PLATFORM_BASE } from './AdaptersPanel';

export type DataSource = { id: string; name: string; adapter_type: string; status: string; source: string };

export const isDemoSource = (c: Pick<DataSource, 'source'>) => c.source === 'seeded_from_env';

type Outcome = ApiOutcome<unknown>;

// Bind and unbind your own Postgres data sources: POST /ai/connections (paid plans; free is a 402
// with the plan's own remedy) and DELETE /ai/connections/{id} (owner only; a lapsed plan can still
// unbind). The list itself is GET /ai/connections, read by the parent. The password is typed into a
// password field, sent once, and cleared whether or not the call succeeded; the API keeps only the
// host, port and database name, and holds the password in the running adapter, not in storage.
export default function ConnectionsPanel({
  apiKey,
  sources,
  onChanged,
}: {
  apiKey: string;
  sources: DataSource[];
  onChanged: () => void;
}) {
  const [name, setName] = useState('');
  const [host, setHost] = useState('');
  const [port, setPort] = useState('5432');
  const [dbUser, setDbUser] = useState('');
  const [password, setPassword] = useState('');
  const [database, setDatabase] = useState('');
  const [ssl, setSsl] = useState('prefer');
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [local, setLocal] = useState('');
  const [bound, setBound] = useState<DataSource | null>(null);
  const [confirming, setConfirming] = useState('');

  const bind = async (e: React.FormEvent) => {
    e.preventDefault();
    setOutcome(null);
    setBound(null);
    setLocal('');
    const portNum = Number(port);
    if (!name.trim() || !host.trim() || !dbUser.trim() || !database.trim() || !password) {
      setLocal('A name, host, user, password and database name are all required.');
      return;
    }
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      setLocal('The port must be a whole number from 1 to 65535.');
      return;
    }
    setBusy(true);
    const out = await call<DataSource>(PLATFORM_BASE, apiKey, '/ai/connections', {
      method: 'POST',
      body: { name: name.trim(), host: host.trim(), port: portNum, user: dbUser.trim(), password, database: database.trim(), ssl_mode: ssl },
    });
    // The password is never kept: gone from state after the one call, success or not.
    setPassword('');
    setBusy(false);
    if (out.kind === 'ok') {
      setBound(out.data);
      setName('');
      onChanged();
    } else {
      setOutcome(out);
    }
  };

  const unbind = async (id: string) => {
    setBusy(true);
    setOutcome(null);
    const out = await call<{ deleted: string }>(PLATFORM_BASE, apiKey, `/ai/connections/${encodeURIComponent(id)}`, { method: 'DELETE' });
    setBusy(false);
    setConfirming('');
    if (out.kind === 'ok') onChanged();
    else setOutcome(out);
  };

  return (
    <section id="ai-sources" aria-labelledby="ai-sources-h">
      <div className="aw-panel-head">
        <h2 id="ai-sources-h">Your data sources</h2>
      </div>
      <div data-testid="sources-list">
        {sources.length === 0 ? (
          <p className="console-empty-note">None are visible to this key. Bind a PostgreSQL database below (paid plans).</p>
        ) : (
          sources.map((c) => (
            <div className={styles.row} key={c.id}>
              <span className={styles.rowMain}>
                <strong>{c.name}</strong> · {c.adapter_type} · status <code>{c.status}</code>{' '}
                {isDemoSource(c) ? (
                  <DemoLabel>Shared demonstration database, not yours</DemoLabel>
                ) : (
                  <span className={styles.tag}>bound by you</span>
                )}
              </span>
              {!isDemoSource(c) &&
                (confirming === c.id ? (
                  <span>
                    <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void unbind(c.id)}>
                      Confirm unbind {c.name}
                    </button>{' '}
                    <button type="button" className="btn btn-secondary" onClick={() => setConfirming('')}>
                      Keep
                    </button>
                  </span>
                ) : (
                  <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => setConfirming(c.id)}>
                    Unbind {c.name}
                  </button>
                ))}
            </div>
          ))
        )}
      </div>

      <h3 style={{ fontSize: '1rem', marginTop: '1rem' }}>Bind a PostgreSQL database</h3>
      <p className="aw-note">
        Calls <code>POST /ai/connections</code> on {PLATFORM_BASE}. Binding saves what you typed; it does not prove the
        database is reachable. Ask &ldquo;health check&rdquo; in the conversation to test it, and read the result as it
        comes. The password is sent once and not kept by this page. The API stores the host, port and database name only
        and keeps the password in the running adapter, so after an API restart you may need to bind again.
      </p>
      <form className={styles.form} onSubmit={bind} autoComplete="off" aria-label="Bind a database">
        <div>
          <label htmlFor="bind-name">Name for this database</label>
          <input id="bind-name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" required />
        </div>
        <div>
          <label htmlFor="bind-host">Host</label>
          <input id="bind-host" value={host} onChange={(e) => setHost(e.target.value)} autoComplete="off" spellCheck={false} required />
        </div>
        <div>
          <label htmlFor="bind-port">Port</label>
          <input id="bind-port" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} autoComplete="off" required />
        </div>
        <div>
          <label htmlFor="bind-dbname">Database name</label>
          <input id="bind-dbname" value={database} onChange={(e) => setDatabase(e.target.value)} autoComplete="off" spellCheck={false} required />
        </div>
        <div>
          <label htmlFor="bind-dbuser">Database user</label>
          <input id="bind-dbuser" value={dbUser} onChange={(e) => setDbUser(e.target.value)} autoComplete="off" spellCheck={false} required />
        </div>
        <div>
          <label htmlFor="bind-dbpass">Database password</label>
          <input id="bind-dbpass" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required />
        </div>
        <div>
          <label htmlFor="bind-ssl">SSL mode</label>
          <select id="bind-ssl" value={ssl} onChange={(e) => setSsl(e.target.value)}>
            <option value="prefer">prefer</option>
            <option value="require">require</option>
            <option value="verify-full">verify-full</option>
            <option value="disable">disable (not for networks you do not control)</option>
          </select>
        </div>
        <div style={{ alignSelf: 'end' }}>
          <button type="submit" className="btn btn-primary" disabled={busy || !apiKey}>
            {busy ? 'Binding…' : apiKey ? 'Bind this database' : 'Paste a key to bind'}
          </button>
        </div>
      </form>
      {local && <Notice>{local}</Notice>}
      {outcome && outcome.kind !== 'ok' && <Refusal outcome={outcome} what="Bind a database" />}
      {bound && (
        <p role="status" className="aw-note" data-testid="bind-success">
          Saved <strong>{bound.name}</strong> (status <code>{bound.status}</code>). Not yet tested: nothing here has
          connected to it.
        </p>
      )}
    </section>
  );
}
