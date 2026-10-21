'use client';

import { useCallback, useEffect, useState } from 'react';
import { useSharedApiKey } from '../lib/apiKey';
import {
  call,
  type ApiOutcome,
  type CaseDetail,
  type CaseQueue,
  type Fleet,
  type ObservationRow,
  type Observations,
} from '../lib/assuranceApi';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

function ageLabel(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return 'unknown age';
  const days = Math.floor((Date.now() - t) / 86_400_000);
  return days <= 0 ? 'today' : `${days} day${days === 1 ? '' : 's'} ago`;
}

const STALE_WHY: Record<string, string> = {
  never_reported: 'never reported',
  never_successfully_observed: 'no successful observation has ever been reported',
  older_than_cadence: 'last successful observation is older than the declared cadence',
};

function when(iso: string | null): string {
  return iso ? `${ageLabel(iso)} (${iso})` : '';
}

// One machine's Watch columns. A failed or incomplete attempt is shown as failed,
// never as an observation; a machine nobody reported is not shown as current.
function ObservationCells({ row }: { row: ObservationRow | undefined }) {
  if (!row || !row.reported) {
    return (
      <>
        <td data-testid="obs-last-success">No Watch report received — run <code>assurance watch push</code></td>
        <td data-testid="obs-last-attempt">—</td>
        <td data-testid="obs-stale">
          <strong className="aw-bad">Stale</strong> — never reported
        </td>
      </>
    );
  }
  const failedLast = row.last_attempt_succeeded === false;
  return (
    <>
      <td data-testid="obs-last-success" title={row.last_successful_observation_at ?? undefined}>
        {row.last_successful_observation_at ? (
          when(row.last_successful_observation_at)
        ) : (
          <span className="aw-bad">None — no successful observation has been reported</span>
        )}
      </td>
      <td data-testid="obs-last-attempt" title={row.last_attempt_at ?? undefined}>
        {failedLast ? (
          <>
            <strong className="aw-bad">FAILED — {row.last_attempt_status}</strong>{' '}
            {row.last_attempt_at ? ageLabel(row.last_attempt_at) : ''}
            {row.consecutive_failed_attempts > 1 ? `, ${row.consecutive_failed_attempts} attempts in a row` : ''}
            <br />
            <span className="aw-note">Not an observation: this machine is not shown as current.</span>
          </>
        ) : (
          <>
            {row.last_attempt_status} {row.last_attempt_at ? ageLabel(row.last_attempt_at) : ''}
          </>
        )}
      </td>
      <td data-testid="obs-stale">
        {row.stale ? (
          <>
            <strong className="aw-bad">Stale</strong> — {STALE_WHY[row.stale_reason] ?? row.stale_reason} (cadence{' '}
            {row.cadence_hours} h{row.cadence_declared ? '' : ', default'})
          </>
        ) : (
          <>No — within {row.cadence_hours} h</>
        )}
      </td>
    </>
  );
}

function Refusal({ outcome, what }: { outcome: ApiOutcome<unknown>; what: string }) {
  if (outcome.kind === 'ok') return null;
  if (outcome.kind === 'unconfigured')
    return (
      <p className="playground-error" role="alert">
        No API is configured for this build (<code>NEXT_PUBLIC_ASSURANCE_API_URL</code>). Nothing is shown rather than
        something invented.
      </p>
    );
  if (outcome.kind === 'unauthorized')
    return (
      <p className="playground-error" role="alert">
        {what}: the API wants a valid key. {outcome.message}
      </p>
    );
  if (outcome.kind === 'upgrade')
    return (
      <p className="playground-error" role="alert">
        {what}: your plan ({outcome.tier}) does not include this. {outcome.remedy}
      </p>
    );
  const message = 'message' in outcome ? outcome.message : '';
  return (
    <p className="playground-error" role="alert">
      {what}: {message || 'request failed'}
    </p>
  );
}

export default function AssuranceWorkspace() {
  const { key, setKey } = useSharedApiKey();
  const [fleet, setFleet] = useState<ApiOutcome<Fleet> | null>(null);
  const [queue, setQueue] = useState<ApiOutcome<CaseQueue> | null>(null);
  const [obs, setObs] = useState<ApiOutcome<Observations> | null>(null);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<string>('');
  const [detail, setDetail] = useState<ApiOutcome<CaseDetail> | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const [f, q, o] = await Promise.all([
      call<Fleet>(API_BASE, key, '/v1/fleet/machines'),
      call<CaseQueue>(API_BASE, key, '/v1/change/cases'),
      call<Observations>(API_BASE, key, '/v1/fleet/observations'),
    ]);
    setFleet(f);
    setQueue(q);
    setObs(o);
    setLoading(false);
  }, [key]);

  useEffect(() => {
    if (key) void load();
  }, [key, load]);

  const open = async (id: string) => {
    setSelected(id);
    setDetail(null);
    setDetail(await call<CaseDetail>(API_BASE, key, `/v1/change/cases/${encodeURIComponent(id)}`));
  };

  return (
    <div className="aw">
      <div className="key-row">
        <label htmlFor="aw-key">API key</label>
        <input
          id="aw-key"
          type="password"
          autoComplete="off"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="Cell-plan key"
        />
        <button className="btn btn-primary" onClick={() => void load()} disabled={loading || !API_BASE}>
          {loading ? 'Loading…' : 'Refresh'}
        </button>
        <span className="key-row-note">
          Kept in this tab only, sent only to the configured API. Your key decides which ledger you read.
        </span>
      </div>

      {!API_BASE && <Refusal outcome={{ kind: 'unconfigured' }} what="Workspace" />}
      {API_BASE && !key && <p className="console-empty-note">Paste a key to load your fleet and cases.</p>}

      <section aria-labelledby="aw-fleet">
        <h2 id="aw-fleet">Fleet</h2>
        {fleet && fleet.kind !== 'ok' && <Refusal outcome={fleet} what="Fleet" />}
        {fleet?.kind === 'ok' && (
          <>
            {!fleet.data.chain_verified && (
              <p className="playground-error" role="alert" data-testid="chain-broken">
                THE LEDGER CHAIN DOES NOT VERIFY — every row below is drawn from a store whose integrity is in question.
                {fleet.data.chain_problems.length ? ` First problem: ${fleet.data.chain_problems[0]}` : ''}
              </p>
            )}
            <p data-testid="fleet-summary">
              {fleet.data.summary.machines} machine(s): {fleet.data.summary.covered} with every declared safety function
              covered, {fleet.data.summary.with_gaps} with gaps.
            </p>
            {fleet.data.machines.length === 0 ? (
              <p className="console-empty-note">
                No machine is enrolled in your ledger. Enrol a machine&apos;s safety manifest with{' '}
                <code>POST /v1/machinery/manifest</code>; until then there is nothing to assess, which is not the same
                as nothing wrong.
              </p>
            ) : (
              <div className="aw-scroll">
                <table className="aw-table" data-testid="fleet-table">
                  <thead>
                    <tr>
                      <th>Machine</th>
                      <th>Site</th>
                      <th>Last sealed manifest</th>
                      <th>Last successful observation</th>
                      <th>Last attempt</th>
                      <th>Stale?</th>
                      <th>Config</th>
                      <th>Evidence</th>
                      <th>Stale</th>
                      <th>Not current</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fleet.data.machines.map((m) => (
                      <tr key={m.machine} data-testid="fleet-row" data-machine={m.machine}>
                        <td>{m.machine}</td>
                        <td>{m.site || '—'}</td>
                        <td title={m.taken_at}>{ageLabel(m.taken_at)}</td>
                        {obs?.kind === 'ok' ? (
                          <ObservationCells row={obs.data.machines.find((r) => r.machine === m.machine)} />
                        ) : (
                          <td colSpan={3} data-testid="obs-unavailable">
                            Observation status unavailable.
                          </td>
                        )}
                        <td>
                          <code>{m.configuration_hash.slice(0, 12)}</code>
                        </td>
                        <td>{m.worst ?? 'no safety function declared'}</td>
                        <td>{m.stale}</td>
                        <td>{m.uncovered}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {obs?.kind === 'ok' &&
              (() => {
                const enrolled = new Set(fleet.data.machines.map((m) => m.machine));
                const extra = obs.data.machines.filter((r) => !enrolled.has(r.machine));
                if (extra.length === 0) return null;
                return (
                  <>
                    <h3>Reported by Watch, no manifest in this ledger</h3>
                    <p className="aw-note">
                      These machines appear only in Watch reports, as attempts that did not produce a manifest here (for
                      example a machine that could not be collected on its first run).
                    </p>
                    <div className="aw-scroll">
                      <table className="aw-table" data-testid="obs-extra-table">
                        <thead>
                          <tr>
                            <th>Machine</th>
                            <th>Last successful observation</th>
                            <th>Last attempt</th>
                            <th>Stale?</th>
                          </tr>
                        </thead>
                        <tbody>
                          {extra.map((r) => (
                            <tr key={r.machine} data-machine={r.machine}>
                              <td>{r.machine}</td>
                              <ObservationCells row={r} />
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                );
              })()}
            {fleet.data.machines.length > 0 && obs?.kind === 'ok' && !obs.data.reporting && (
              <p className="console-empty-note" data-testid="obs-none">
                No Watch report received — run <code>assurance watch push</code>. Until you do, this workspace only
                knows the manifests that were recorded in it; it cannot say when any machine was last looked at.
              </p>
            )}
            {obs?.kind === 'ok' && obs.data.reporting && (
              <p data-testid="obs-summary">
                {obs.data.summary.stale} stale · {obs.data.summary.latest_attempt_failed} whose latest attempt failed ·{' '}
                {obs.data.summary.never_reported} never reported. Reported by you, not independently observed; each
                machine is judged against the cadence your Watch declared with its last successful look (default{' '}
                {obs.data.default_cadence_hours} h).
              </p>
            )}
            {obs && obs.kind !== 'ok' && fleet.kind === 'ok' && <Refusal outcome={obs} what="Observations" />}
            <p className="aw-note">
              &ldquo;Last sealed manifest&rdquo; is the last configuration recorded in this ledger, not a live
              observation. The hosted API does not run Watch: Watch still runs in your kit or scheduler, and the
              observation columns show only what you chose to report with <code>assurance watch push</code>. A look that
              failed or was incomplete is shown as failed, never as unchanged, and a machine whose last successful
              observation is older than your declared cadence, or that was never reported, is shown as stale. These
              are your reports; the hosted service did not observe any machine.
            </p>
          </>
        )}
      </section>

      <section aria-labelledby="aw-cases">
        <h2 id="aw-cases">Change-assurance cases</h2>
        {queue && queue.kind !== 'ok' && <Refusal outcome={queue} what="Cases" />}
        {queue?.kind === 'ok' && (
          <>
            <p data-testid="case-summary">
              {queue.data.summary.open} open · {queue.data.summary.safety_relevant} safety-relevant ·{' '}
              {queue.data.summary.awaiting_reverification} awaiting re-verification · {queue.data.summary.ready_to_close}{' '}
              ready for a human decision
            </p>
            {queue.data.cases.length === 0 ? (
              <p className="console-empty-note">No cases. A case opens when Watch or an assessment finds a change or advisory.</p>
            ) : (
              <div className="aw-scroll">
                <table className="aw-table" data-testid="case-table">
                  <thead>
                    <tr>
                      <th>Case</th>
                      <th>Status</th>
                      <th>Machines</th>
                      <th>Safety functions in question</th>
                      <th>Evidence</th>
                      <th>Owner</th>
                      <th>Next action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {queue.data.cases.map((c) => (
                      <tr key={c.case_id} className={c.case_id === selected ? 'aw-selected' : ''}>
                        <td>
                          <button className="aw-link" onClick={() => void open(c.case_id)}>
                            {c.case_id}
                          </button>
                        </td>
                        <td>{c.status}</td>
                        <td>{c.machines.join(', ')}</td>
                        <td>{c.affected_functions.join(', ') || '—'}</td>
                        <td>{c.evidence_state.join(', ')}</td>
                        <td>{c.owner || 'unassigned'}</td>
                        <td>{c.next_action}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </section>

      {selected && (
        <CaseDetailPanel
          caseId={selected}
          apiKey={key}
          detail={detail}
          onChanged={async () => {
            await open(selected);
            await load();
          }}
        />
      )}
    </div>
  );
}

function CaseDetailPanel({
  caseId,
  apiKey,
  detail,
  onChanged,
}: {
  caseId: string;
  apiKey: string;
  detail: ApiOutcome<CaseDetail> | null;
  onChanged: () => Promise<void>;
}) {
  const [actor, setActor] = useState('');
  const [owner, setOwner] = useState('');
  const [reason, setReason] = useState('');
  const [manifest, setManifest] = useState('');
  const [verifHash, setVerifHash] = useState('');
  const [result, setResult] = useState<ApiOutcome<unknown> | null>(null);
  const [exported, setExported] = useState('');

  const act = async (path: string, body: Record<string, unknown>) => {
    setResult(null);
    const out = await call<unknown>(API_BASE, apiKey, `/v1/change/cases/${encodeURIComponent(caseId)}/${path}`, {
      method: 'POST',
      body,
    });
    setResult(out);
    if (out.kind === 'ok') await onChanged();
  };

  const needActor = () => {
    if (actor.trim()) return true;
    setResult({ kind: 'conflict', message: 'Enter the name of the person taking this action — it is recorded.' });
    return false;
  };

  const download = async () => {
    setExported('');
    const out = await call<unknown>(API_BASE, apiKey, `/v1/cases/${encodeURIComponent(caseId)}/export`);
    if (out.kind !== 'ok') {
      setResult(out);
      return;
    }
    const url = URL.createObjectURL(new Blob([JSON.stringify(out.data, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `case-${caseId}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setExported(`case-${caseId}.json`);
  };

  if (!detail) return <p className="console-empty-note">Loading case…</p>;
  if (detail.kind !== 'ok') return <Refusal outcome={detail} what={`Case ${caseId}`} />;
  const c = detail.data;
  const settled = ['closed', 'rejected'].includes(c.status);

  return (
    <section aria-labelledby="aw-detail" className="aw-detail" data-testid="case-detail">
      <h2 id="aw-detail">
        Case {c.case_id} — {c.status}
      </h2>
      <p>
        Trigger: {c.trigger_type} / <code>{c.trigger_id.slice(0, 16)}</code> · severity: {c.change_severity || 'not assessed'} ·
        machines: {c.machines.join(', ')}
      </p>
      {c.invalidation_reason && <p>Why evidence is in question: {c.invalidation_reason}</p>}

      <div className="aw-cols">
        <div>
          <h3>Safety functions and evidence</h3>
          <ul>
            {Object.entries(c.evidence_current).map(([fn, state]) => (
              <li key={fn}>
                {fn}: <strong>{state}</strong>
              </li>
            ))}
            {Object.keys(c.evidence_current).length === 0 && <li>None recorded.</li>}
          </ul>
          <h3>Required actions</h3>
          <ul>{c.required_actions.map((a) => <li key={a}>{a}</li>)}{c.required_actions.length === 0 && <li>None outstanding.</li>}</ul>
          <h3>Required re-verification</h3>
          <ul>{c.required_reverifications.map((a) => <li key={a}>{a}</li>)}{c.required_reverifications.length === 0 && <li>None outstanding.</li>}</ul>
          <h3>Human decisions required</h3>
          <ul>{c.human_decisions_required.map((a) => <li key={a}>{a}</li>)}{c.human_decisions_required.length === 0 && <li>None outstanding.</li>}</ul>
        </div>
        <div>
          <h3>Source evidence</h3>
          <ul>
            {c.linked_evidence.map((r, i) => (
              <li key={i}>
                {r.relation || 'evidence'} <code>{(r.content_hash || '').slice(0, 16)}</code> {r.note}
              </li>
            ))}
            {c.linked_evidence.length === 0 && <li>None linked.</li>}
          </ul>
          <h3>What this does not establish</h3>
          <ul>{c.checks_skipped.map((s) => <li key={s}>{s}</li>)}</ul>
        </div>
      </div>

      <h3>History — who did what</h3>
      <ol data-testid="case-history">
        {c.history.map((h, i) => (
          <li key={i}>
            <time dateTime={h.at}>{h.at}</time> · {h.kind} · {h.detail}
          </li>
        ))}
      </ol>
      {c.decision && (
        <p>
          Decision: <strong>{c.decision}</strong> by {c.decision_by || 'unknown'} — {c.decision_reason}
        </p>
      )}

      {!settled && (
        <div className="aw-actions">
          <h3>Actions (recorded under your name)</h3>
          <label>
            Your name
            <input value={actor} onChange={(e) => setActor(e.target.value)} />
          </label>
          <div className="aw-row">
            <label>
              Owner
              <input value={owner} onChange={(e) => setOwner(e.target.value)} />
            </label>
            <button
              className="btn btn-outline"
              onClick={() => needActor() && owner.trim() && void act('claim', { owner: owner.trim(), actor: actor.trim() })}
            >
              Claim
            </button>
            <button className="btn btn-outline" onClick={() => needActor() && void act('advance', { actor: actor.trim() })}>
              Advance
            </button>
          </div>
          <details>
            <summary>Submit re-verification evidence</summary>
            <label>
              Safety manifest (JSON) the verification was made against
              <textarea rows={5} value={manifest} onChange={(e) => setManifest(e.target.value)} />
            </label>
            <label>
              Verification content hash
              <input value={verifHash} onChange={(e) => setVerifHash(e.target.value)} />
            </label>
            <button
              className="btn btn-outline"
              onClick={() => {
                if (!needActor()) return;
                let parsed: unknown;
                try {
                  parsed = JSON.parse(manifest);
                } catch {
                  setResult({ kind: 'conflict', message: 'That manifest is not valid JSON.' });
                  return;
                }
                void act('reverification', {
                  manifest: parsed,
                  verification_content_hash: verifHash.trim(),
                  actor: actor.trim(),
                });
              }}
            >
              Submit
            </button>
          </details>
          <label>
            Decision reason
            <textarea rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />
          </label>
          <div className="aw-row">
            {(['closed', 'deferred', 'rejected'] as const).map((d) => (
              <button
                key={d}
                className="btn btn-outline"
                onClick={() =>
                  needActor() &&
                  (reason.trim()
                    ? void act('decision', { disposition: d, reason: reason.trim(), actor: actor.trim() })
                    : setResult({ kind: 'conflict', message: 'A decision needs a reason.' }))
                }
              >
                {d === 'closed' ? 'Close' : d === 'deferred' ? 'Defer' : 'Reject'}
              </button>
            ))}
          </div>
          <p className="aw-note">
            The server decides whether a case may close: it refuses until the underlying evidence is current and every
            human question is answered, whatever this page sends.
          </p>
        </div>
      )}
      {result && result.kind !== 'ok' && <Refusal outcome={result} what="Action" />}

      <div className="aw-export">
        <h3>Evidence export</h3>
        <button className="btn btn-secondary" onClick={() => void download()}>
          Download this case&apos;s evidence
        </button>
        {exported && (
          <p data-testid="export-done">
            Saved <code>{exported}</code>. Anyone can check it offline, without an account:{' '}
            <code>python -m assurance evidence verify {exported}</code>. That proves the file is internally consistent
            and untampered; to show it matches the ledger as held, check a signed head attestation.
          </p>
        )}
      </div>
    </section>
  );
}
