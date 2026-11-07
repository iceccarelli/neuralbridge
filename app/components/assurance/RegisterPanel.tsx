'use client';

import { useState } from 'react';
import type { Art14Register } from '../../lib/assuranceApi';
import { PanelFrame } from './PanelFrame';
import { API_BASE, usePanel } from './usePanel';
import styles from './workspace.module.css';

// The CRA Article 14 register, read from GET /v1/register. This replaces the retired dashboard's
// "compliance" screen, which showed invented percentages. Here every figure is a record someone
// made: awareness, the Art. 14 track and the submissions are human declarations that the register
// stores and recomputes deadlines from. Nothing on this panel says a product, a machine or an
// organisation complies with anything, and it records nothing.
//
// It is read on request, not on page load: the report recomputes every case's deadlines, and a key
// whose plan does not include it should meet that refusal when it asks, not on every visit.
export default function RegisterPanel({ apiKey }: { apiKey: string }) {
  const [requested, setRequested] = useState(false);
  if (!requested) {
    return (
      <section id="aw-register" aria-labelledby="aw-register-h">
        <div className="aw-panel-head">
          <h2 id="aw-register-h">CRA Article 14 register (read-only)</h2>
        </div>
        <p className="aw-note">
          Reads <code>GET /v1/register</code>: the Article 14 cases recorded in your ledger, with the deadlines
          recomputed from what people declared. It records nothing and files nothing.
        </p>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => setRequested(true)}
          disabled={!API_BASE || !apiKey}
          data-testid="register-load"
        >
          {!API_BASE ? 'No API configured' : apiKey ? 'Load the register' : 'Paste a key to load the register'}
        </button>
      </section>
    );
  }
  return <RegisterLoaded apiKey={apiKey} />;
}

function RegisterLoaded({ apiKey }: { apiKey: string }) {
  const register = usePanel<Art14Register>(apiKey, '/v1/register');
  return (
    <PanelFrame id="aw-register" title="CRA Article 14 register (read-only)" what="the Article 14 register" apiKey={apiKey} panel={register}>
      {(r) => (
        <div data-testid="register-panel">
          <p className="aw-note">
            {r.regulation}, applicable since {r.applicable_since}. This is a view of what was recorded in your ledger:
            awareness, the track and every submission are declarations by named people, and the platform verifies none of
            them. Software drafts; people decide and file.
          </p>
          <p data-testid="register-chain">
            Ledger: {r.ledger.records} record{r.ledger.records === 1 ? '' : 's'}; chain{' '}
            <strong>{r.ledger.chain_verified ? 'verified on this request' : 'NOT verified'}</strong>
            {r.ledger.problems.length > 0 && `: ${r.ledger.problems.join('; ')}`}.
          </p>

          {r.cases.length === 0 && r.unreadable_cases.length === 0 ? (
            <p className="console-empty-note" data-testid="register-empty">
              No Article 14 case is recorded in this ledger. An empty register means nothing was recorded here, not that
              nothing happened.
            </p>
          ) : (
            <div className={styles.scroll}>
              <table className={styles.table} data-testid="register-table">
                <caption className="aw-visually-hidden">Article 14 cases recorded in this ledger</caption>
                <thead>
                  <tr>
                    <th scope="col">Case</th>
                    <th scope="col">State</th>
                    <th scope="col">Track</th>
                    <th scope="col">Awareness recorded</th>
                    <th scope="col">Deadlines</th>
                    <th scope="col">Outstanding</th>
                  </tr>
                </thead>
                <tbody>
                  {r.cases.map((c) => (
                    <tr key={c.case_id}>
                      <td><code>{c.case_id}</code></td>
                      <td>{c.state}</td>
                      <td>{c.track ?? 'not recorded'}</td>
                      <td>{c.awareness ? 'yes (by a person)' : 'no'}</td>
                      <td>
                        {c.deadlines ? (
                          <ul style={{ margin: 0, paddingLeft: '1rem' }}>
                            {c.deadlines.deadlines.map((d) => (
                              <li key={d.stage}>
                                {d.stage_label}: due {d.due_at}, <strong>{d.status}</strong>
                                {d.submitted_at ? `; declared submitted ${d.submitted_at}` : ''}
                                {d.verified_by_platform ? '' : ' (not verified by the platform)'}
                              </li>
                            ))}
                          </ul>
                        ) : (
                          'none computable yet'
                        )}
                      </td>
                      <td>{c.outstanding.length === 0 ? 'none recorded' : c.outstanding.join(' · ')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {r.unreadable_cases.length > 0 && (
            <div className="aw-alert" role="alert" data-outcome="partial">
              <strong>{r.unreadable_cases.length} case{r.unreadable_cases.length === 1 ? '' : 's'} could not be read.</strong>{' '}
              They are listed, not dropped: {r.unreadable_cases.map((u) => `${u.case_id} (${u.error})`).join('; ')}
            </div>
          )}

          <h3 style={{ fontSize: '1rem', marginTop: '1rem' }}>Deadlines missed or recorded incomplete</h3>
          {r.breaches.length === 0 ? (
            <p className="aw-note">None in what is recorded. Events never recorded are invisible to this register.</p>
          ) : (
            <ul data-testid="register-breaches">
              {r.breaches.map((b, i) => (
                <li key={`${b.case_id}-${b.stage}-${i}`}>
                  <code>{b.case_id}</code> · {b.stage} · {b.status}
                  {b.due_at ? ` · due ${b.due_at}` : ''}
                </li>
              ))}
            </ul>
          )}

          <details style={{ marginTop: '0.75rem' }}>
            <summary>What this register does not check ({r.checks_skipped.length})</summary>
            <ul>
              {r.checks_skipped.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          </details>
        </div>
      )}
    </PanelFrame>
  );
}
