'use client';

import { useState } from 'react';
import { call, type ApiOutcome, type CaseDetail, type ExportBundle, type HistoryItem } from '../../lib/assuranceApi';
import { Notice, PanelFrame, Refusal } from './PanelFrame';
import { API_BASE, usePanel } from './usePanel';

type Who = { text: string; title: string };

// The case's own history says what happened and when; WHO is sealed on each event's
// ledger entry. Every history item is exactly one ledger entry of the case's subject, in
// order (the replay check rejects anything else), so the i-th entry is the i-th item. If
// the counts or kinds do not line up, nothing is guessed.
export function attributeHistory(history: HistoryItem[], bundle: ExportBundle | null, caseId: string): Who[] | null {
  if (!bundle || !Array.isArray(bundle.entries)) return null;
  const entries = bundle.entries
    .filter((e) => e.subject === caseId && String(e.kind).startsWith('assurance.change.'))
    .sort((a, b) => a.seq - b.seq);
  if (entries.length !== history.length) return null;
  if (entries.some((e, i) => e.kind !== history[i].kind)) return null;
  return entries.map((e) => {
    const a = (e as { evidence?: { actor?: { identifier?: string; role?: string; kind?: string } } }).evidence?.actor;
    const name = a?.identifier || (typeof e.actor === 'string' ? e.actor : '');
    if (!name) return { text: 'not recorded', title: '' };
    return { text: `${name} (${a?.kind || 'actor'})`, title: a?.role || '' };
  });
}

export default function CaseDetailPanel({
  apiKey,
  caseId,
  actor,
  setActor,
  onChanged,
}: {
  apiKey: string;
  caseId: string;
  actor: string;
  setActor: (v: string) => void;
  onChanged: () => void;
}) {
  const enc = encodeURIComponent(caseId);
  const detail = usePanel<CaseDetail>(apiKey, `/v1/change/cases/${enc}`);
  // Who did each step comes from the case's evidence export. Its failure costs the "who" column and nothing else.
  const bundle = usePanel<ExportBundle>(apiKey, detail.outcome?.kind === 'ok' ? `/v1/cases/${enc}/export` : null);

  const [owner, setOwner] = useState('');
  const [reason, setReason] = useState('');
  const [manifest, setManifest] = useState('');
  const [verifHash, setVerifHash] = useState('');
  const [result, setResult] = useState<ApiOutcome<unknown> | null>(null);
  const [notice, setNotice] = useState('');
  const [exported, setExported] = useState<{ file: string; entries: number } | null>(null);
  const [busy, setBusy] = useState(false);

  const act = async (path: string, body: Record<string, unknown>) => {
    setResult(null);
    setNotice('');
    setBusy(true);
    const out = await call<unknown>(API_BASE, apiKey, `/v1/change/cases/${enc}/${path}`, { method: 'POST', body });
    setBusy(false);
    setResult(out);
    if (out.kind === 'ok') {
      await Promise.all([detail.reload(), bundle.reload()]);
      onChanged();
    }
  };

  const needActor = () => {
    if (actor.trim()) return true;
    setResult(null);
    setNotice('Enter the name of the person taking this action — it is recorded.');
    return false;
  };

  const download = async () => {
    setExported(null);
    setNotice('');
    setResult(null);
    const out = await call<ExportBundle>(API_BASE, apiKey, `/v1/cases/${enc}/export`);
    if (out.kind !== 'ok') {
      setResult(out);
      return;
    }
    // An unknown id (or another account's) exports as a bundle with no entries. Saving that as
    // "this case's evidence" would be a file that proves nothing under a name that implies it does.
    if (!Array.isArray(out.data.entries) || out.data.entries.length === 0) {
      setNotice(
        `The ledger holds no entries for ${caseId}, so nothing was saved. An empty file would look like evidence and contain none.`,
      );
      return;
    }
    if (out.data.chain_verified !== true) {
      setNotice('The server did not state that the ledger chain verified at export time, so nothing was saved.');
      return;
    }
    const url = URL.createObjectURL(new Blob([JSON.stringify(out.data, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `case-${caseId}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setExported({ file: `case-${caseId}.json`, entries: out.data.entries.length });
  };

  return (
    <PanelFrame id="aw-case" title={`Case ${caseId}`} what="the case" apiKey={apiKey} panel={detail}>
      {(c) => {
        const settled = ['closed', 'rejected'].includes(c.status);
        const bundleData = bundle.outcome?.kind === 'ok' ? bundle.outcome.data : null;
        const who = attributeHistory(c.history, bundleData, c.case_id);
        const whoPending = bundle.outcome === null || (bundle.loading && !bundleData);
        const whoState = who ? 'ready' : whoPending ? 'loading' : 'unavailable';
        const reverifyEvents = c.history.filter((h) => h.kind === 'assurance.change.reverification');
        return (
          <div className="aw-detail" data-testid="case-detail">
            <h3>
              {c.case_id} — {c.status}
            </h3>
            <p>
              Trigger: {c.trigger_type} / <code>{c.trigger_id.slice(0, 16)}</code> · severity:{' '}
              {c.change_severity || 'not assessed'} · machines: {c.machines.join(', ')}
              {c.opened_at ? ` · opened ${c.opened_at}` : ''}
            </p>
            {c.invalidation_reason && <p>Why evidence is in question: {c.invalidation_reason}</p>}

            <div className="aw-cols">
              <div>
                <h4>Safety functions and evidence</h4>
                <ul>
                  {Object.entries(c.evidence_current).map(([fn, state]) => (
                    <li key={fn}>
                      {fn}: <strong>{state}</strong>
                    </li>
                  ))}
                  {Object.keys(c.evidence_current).length === 0 && <li>None recorded.</li>}
                </ul>
                <h4>Required actions</h4>
                <ul>
                  {c.required_actions.map((a) => (
                    <li key={a}>{a}</li>
                  ))}
                  {c.required_actions.length === 0 && <li>None outstanding.</li>}
                </ul>
                <h4>Required re-verification</h4>
                <ul data-testid="required-reverifications">
                  {c.required_reverifications.map((a) => (
                    <li key={a}>{a}</li>
                  ))}
                  {c.required_reverifications.length === 0 && <li>None outstanding.</li>}
                </ul>
                <p className="aw-note">
                  {reverifyEvents.length === 0
                    ? 'No re-verification has been submitted for this case.'
                    : `${reverifyEvents.length} re-verification submission(s) so far: see the history below for when and by whom.`}
                </p>
                <h4>Human decisions required</h4>
                <ul>
                  {c.human_decisions_required.map((a) => (
                    <li key={a}>{a}</li>
                  ))}
                  {c.human_decisions_required.length === 0 && <li>None outstanding.</li>}
                </ul>
              </div>
              <div>
                <h4>Source evidence</h4>
                <ul>
                  {c.linked_evidence.map((r, i) => (
                    <li key={i}>
                      {r.relation || 'evidence'} <code>{(r.content_hash || '').slice(0, 16)}</code> {r.note}
                    </li>
                  ))}
                  {c.linked_evidence.length === 0 && <li>None linked.</li>}
                </ul>
                <h4>What this does not establish</h4>
                <ul>
                  {c.checks_skipped.map((s) => (
                    <li key={s}>{s}</li>
                  ))}
                </ul>
              </div>
            </div>

            <h4>History — what happened, when, and who</h4>
            <div className="aw-scroll">
              <table className="aw-table" data-testid="case-history" data-who={whoState}>
                <thead>
                  <tr>
                    <th>When</th>
                    <th>What</th>
                    <th>Detail</th>
                    <th>Who</th>
                  </tr>
                </thead>
                <tbody>
                  {c.history.map((h, i) => (
                    <tr key={i} data-testid="history-row">
                      <td data-testid="history-when">
                        <time dateTime={h.at}>{h.at}</time>
                      </td>
                      <td>{h.kind.replace('assurance.change.', '')}</td>
                      <td>{h.detail}</td>
                      <td data-testid="history-who" title={who?.[i]?.title}>
                        {who
                          ? who[i].text
                          : whoPending
                            ? 'loading…'
                            : 'not available — the evidence export that carries it was not received'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!who && !whoPending && (
              <>
                {bundle.outcome && bundle.outcome.kind !== 'ok' ? (
                  <Refusal outcome={bundle.outcome} what="Who did each step (evidence export)" />
                ) : (
                  <p className="aw-note">
                    The actors could not be matched to the history one-to-one, so none is shown rather than a guess.
                  </p>
                )}
              </>
            )}
            <p className="aw-note">
              &ldquo;Who&rdquo; is the name the account holder declared for that step, sealed on its ledger entry. It is
              not identity-proofed.
            </p>
            {c.decision && (
              <p>
                Decision: <strong>{c.decision}</strong> by {c.decision_by || 'unknown'} — {c.decision_reason}
              </p>
            )}

            {!settled && (
              <div className="aw-actions">
                <h4>Actions (recorded under your name)</h4>
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
                    disabled={busy}
                    onClick={() => needActor() && owner.trim() && void act('claim', { owner: owner.trim(), actor: actor.trim() })}
                  >
                    Claim
                  </button>
                  <button
                    className="btn btn-outline"
                    disabled={busy}
                    onClick={() => needActor() && void act('advance', { actor: actor.trim() })}
                  >
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
                    disabled={busy}
                    onClick={() => {
                      if (!needActor()) return;
                      let parsed: unknown;
                      try {
                        parsed = JSON.parse(manifest);
                      } catch {
                        setResult(null);
                        setNotice('That manifest is not valid JSON.');
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
                      disabled={busy}
                      onClick={() => {
                        if (!needActor()) return;
                        if (!reason.trim()) {
                          setResult(null);
                          setNotice('A decision needs a reason.');
                          return;
                        }
                        void act('decision', { disposition: d, reason: reason.trim(), actor: actor.trim() });
                      }}
                    >
                      {d === 'closed' ? 'Close' : d === 'deferred' ? 'Defer' : 'Reject'}
                    </button>
                  ))}
                </div>
                <p className="aw-note">
                  The server decides whether a case may close: it refuses until the underlying evidence is current and
                  every human question is answered, whatever this page sends.
                </p>
              </div>
            )}
            {notice && <Notice>{notice}</Notice>}
            {result && result.kind !== 'ok' && <Refusal outcome={result} what="Action" />}

            <div className="aw-export">
              <h4>Evidence export</h4>
              <button className="btn btn-secondary" onClick={() => void download()}>
                Download this case&apos;s evidence
              </button>{' '}
              <a href="/verify">Verify this export</a>
              {exported && (
                <p data-testid="export-done">
                  Saved <code>{exported.file}</code> ({exported.entries} ledger entries; the server reported the chain as
                  verified when it built the file). Anyone can check it offline, without an account:{' '}
                  <code>python -m assurance evidence verify {exported.file}</code>. That shows the file is internally
                  consistent and untampered; it does not show that it matches the ledger as held. For that, check a signed
                  head attestation.
                </p>
              )}
              {!exported && (
                <p className="aw-note">
                  The offline check shows an export is internally consistent and untampered. It does not show that the
                  export matches the ledger as held; that needs a signed head attestation.
                </p>
              )}
            </div>
          </div>
        );
      }}
    </PanelFrame>
  );
}
