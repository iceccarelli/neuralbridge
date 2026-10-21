'use client';

import { useCallback, useEffect, useState } from 'react';
import { useSharedApiKey } from '../lib/apiKey';
import {
  call,
  type ApiOutcome,
  type CaseDetail,
  type CaseQueue,
  type Fleet,
} from '../lib/assuranceApi';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

function ageLabel(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return 'unknown age';
  const days = Math.floor((Date.now() - t) / 86_400_000);
  return days <= 0 ? 'today' : `${days} day${days === 1 ? '' : 's'} ago`;
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
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<string>('');
  const [detail, setDetail] = useState<ApiOutcome<CaseDetail> | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const [f, q] = await Promise.all([
      call<Fleet>(API_BASE, key, '/v1/fleet/machines'),
      call<CaseQueue>(API_BASE, key, '/v1/change/cases'),
    ]);
    setFleet(f);
    setQueue(q);
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
                      <th>Config</th>
                      <th>Evidence</th>
                      <th>Stale</th>
                      <th>Not current</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fleet.data.machines.map((m) => (
                      <tr key={m.machine}>
                        <td>{m.machine}</td>
                        <td>{m.site || '—'}</td>
                        <td title={m.taken_at}>{ageLabel(m.taken_at)}</td>
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
            <p className="aw-note">
              &ldquo;Last sealed manifest&rdquo; is the last configuration recorded in this ledger, not a live
              observation: the hosted API does not run Watch. Watch runs in your kit or scheduler and a failed or missed
              run is not recorded here, so an old date means the record is old, not that the machine is unchanged.
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
