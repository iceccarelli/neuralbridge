'use client';

import { useState } from 'react';
import { call, type ApiOutcome, type CaseDetail, type ExportBundle, type HistoryItem, type Replay } from '../../lib/assuranceApi';
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

// The words the server sealed for a waiver: "re-verification of <entry> waived by <name>: <reason>".
function waiverText(history: HistoryItem[], entry: string): string {
  const prefix = `re-verification of ${entry} `;
  const h = [...history]
    .reverse()
    .find((x) => x.detail.startsWith(prefix) && x.detail.slice(prefix.length).startsWith('waived by'));
  return h ? h.detail.slice(prefix.length) : '';
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
  const bundle = usePanel<ExportBundle>(apiKey, detail.outcome?.kind === 'ok' ? `/v1/change/cases/${enc}/export` : null);

  const [owner, setOwner] = useState('');
  const [reason, setReason] = useState('');
  const [manifest, setManifest] = useState('');
  const [verifHash, setVerifHash] = useState('');
  const [result, setResult] = useState<ApiOutcome<unknown> | null>(null);
  const [notice, setNotice] = useState('');
  const [exported, setExported] = useState<{ file: string; entries: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState('');
  const [entry, setEntry] = useState('');
  const [waiver, setWaiver] = useState('');
  const [resumeWhy, setResumeWhy] = useState('');
  const [replay, setReplay] = useState<ApiOutcome<Replay> | null>(null);
  const [replaying, setReplaying] = useState(false);

  const runReplay = async () => {
    setReplay(null);
    setReplaying(true);
    setReplay(await call<Replay>(API_BASE, apiKey, `/v1/change/cases/${enc}/replay`));
    setReplaying(false);
  };

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
    const out = await call<ExportBundle>(API_BASE, apiKey, `/v1/change/cases/${enc}/export`);
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
    <PanelFrame
      id="aw-case"
      title={`Case ${caseId}`}
      what="the case"
      apiKey={apiKey}
      panel={detail}
      notFoundNote="Only your own ledger is searched. A case that belongs to another account reads exactly like one that does not exist."
    >
      {(c) => {
        const settled = ['closed', 'rejected'].includes(c.status);
        const deferred = c.status === 'deferred';
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
                  {Object.entries(c.evidence_current).map(([fn, state]) => {
                    // A waiver is a person's decision to close an entry WITHOUT evidence. It is shown as
                    // exactly that, with the words the server sealed, and never as current or verified.
                    const waived = state === 'waived' ? waiverText(c.history, fn) : '';
                    return (
                      <li key={fn} data-testid="evidence-row" data-entry={fn} data-state={state}>
                        {fn}: <strong>{state}</strong>
                        {state === 'waived' && <> — {waived || 'waived without evidence (see the history for who and why)'}</>}
                      </li>
                    );
                  })}
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
                {(c.resolved_decisions ?? []).length > 0 && (
                  <>
                    <h4>Resolved human decisions</h4>
                    <ul data-testid="resolved-decisions">
                      {(c.resolved_decisions ?? []).map((r, i) => (
                        <li key={i}>
                          {r.decision} — <em>{r.resolution}</em>
                          {r.by ? ` (${r.by}${r.at ? `, ${r.at}` : ''})` : ''}
                        </li>
                      ))}
                    </ul>
                  </>
                )}
                <div className="aw-note" data-testid="reverify-howto">
                  <strong>How a re-verification becomes evidence.</strong> The only evidence that can clear an entry is
                  a verification sealed for <em>that machine</em>: (1) seal the machine&apos;s current manifest with{' '}
                  <code>POST /v1/machinery/manifest</code>; (2) run <code>POST /v1/machine/verify</code> with{' '}
                  <code>subject</code> set to the machine key (<code>manufacturer/model#serial</code>) — without a{' '}
                  <code>subject</code> the bundle is filed under the product line and can never clear a case; (3) submit
                  that manifest below with the <code>content_hash</code> that call returned as{' '}
                  <code>verification_content_hash</code>. The server checks the hash against the ledger. There is no way
                  to mark an entry verified from this page; closing one without evidence is the explicit waiver, which
                  reads &ldquo;waived&rdquo;.
                </div>
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

            {deferred && (
              <div className="aw-actions">
                <h4>Deferred — not settled</h4>
                <p className="aw-note">
                  A person decided not to act yet. The case still needs its eventual decision. Resuming puts it back in
                  review and must be advanced again; it needs a named person and a reason.
                </p>
                <label>
                  Your name
                  <input value={actor} onChange={(e) => setActor(e.target.value)} />
                </label>
                <label>
                  Why resume
                  <textarea rows={2} value={resumeWhy} onChange={(e) => setResumeWhy(e.target.value)} />
                </label>
                <button
                  className="btn btn-outline"
                  disabled={busy}
                  onClick={() => {
                    if (!needActor()) return;
                    if (!resumeWhy.trim()) {
                      setResult(null);
                      setNotice('Resuming a case needs a reason.');
                      return;
                    }
                    void act('resume', { reason: resumeWhy.trim(), actor: actor.trim() });
                  }}
                >
                  Resume case
                </button>
              </div>
            )}
            {!settled && !deferred && (
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
                {c.human_decisions_required.length > 0 && (
                  <>
                    <h4>Answer a human question</h4>
                    <label>
                      Question
                      <select value={question || c.human_decisions_required[0]} onChange={(e) => setQuestion(e.target.value)}>
                        {c.human_decisions_required.map((q) => (
                          <option key={q} value={q}>
                            {q}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      Answer
                      <textarea rows={2} value={answer} onChange={(e) => setAnswer(e.target.value)} />
                    </label>
                    <button
                      className="btn btn-outline"
                      disabled={busy}
                      onClick={() => {
                        if (!needActor()) return;
                        if (!answer.trim()) {
                          setResult(null);
                          setNotice('An answer needs the decision the person actually made.');
                          return;
                        }
                        void act('resolve-decision', {
                          decision: c.human_decisions_required.includes(question) ? question : c.human_decisions_required[0],
                          resolution: answer.trim(),
                          actor: actor.trim(),
                        });
                      }}
                    >
                      Record answer
                    </button>
                  </>
                )}
                {c.required_reverifications.length > 0 && (
                  <>
                    <h4>Waive a re-verification</h4>
                    <p className="aw-note" data-testid="waive-warning">
                      This closes the entry <strong>without evidence</strong>. It is recorded under your name with your
                      reason, and it reads &ldquo;waived&rdquo; here and in every export &mdash; never current or
                      verified. Use it only when a person accepts that nothing will verify this entry.
                    </p>
                    <label>
                      Re-verification entry
                      <select value={entry || c.required_reverifications[0]} onChange={(e) => setEntry(e.target.value)}>
                        {c.required_reverifications.map((q) => (
                          <option key={q} value={q}>
                            {q}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      Why closing it without evidence is acceptable
                      <textarea rows={2} value={waiver} onChange={(e) => setWaiver(e.target.value)} />
                    </label>
                    <button
                      className="btn btn-outline"
                      disabled={busy}
                      onClick={() => {
                        if (!needActor()) return;
                        if (!waiver.trim()) {
                          setResult(null);
                          setNotice('A waiver needs a reason: why closing without evidence is acceptable.');
                          return;
                        }
                        void act('waive-reverification', {
                          entry: c.required_reverifications.includes(entry) ? entry : c.required_reverifications[0],
                          reason: waiver.trim(),
                          actor: actor.trim(),
                        });
                      }}
                    >
                      Waive without evidence
                    </button>
                  </>
                )}
                <h4>Decide</h4>
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
              <h4>Check this case against the ledger</h4>
              <p className="aw-note">
                Rebuilds the case from the ledger&apos;s own entries and rejects any step the lifecycle would not have
                allowed. It does not show that the evidence is adequate: a person still decides that.
              </p>
              <button className="btn btn-secondary" disabled={replaying} onClick={() => void runReplay()}>
                Check this case against the ledger
              </button>
              {replaying && (
                <p className="aw-note" role="status">
                  Replaying…
                </p>
              )}
              {replay && replay.kind !== 'ok' && <Refusal outcome={replay} what="Replay" />}
              {replay?.kind === 'ok' && (
                <div
                  className={replay.data.ok ? 'aw-prov' : 'aw-alert'}
                  role={replay.data.ok ? 'status' : 'alert'}
                  data-testid="replay-result"
                  data-ok={replay.data.ok ? 'true' : 'false'}
                >
                  {replay.data.ok ? (
                    <p>
                      {replay.data.entries} ledger entr{replay.data.entries === 1 ? 'y' : 'ies'} rebuild this case, and
                      every step was legal. That does not show the evidence is adequate; a person still decides that.
                    </p>
                  ) : (
                    <>
                      <p>
                        <strong>THIS CASE DOES NOT REPLAY CLEANLY</strong> — the ledger&apos;s entries do not reproduce
                        the state shown above. Do not rely on it until each of these is explained:
                      </p>
                      <ul>
                        {replay.data.violations.map((v) => (
                          <li key={v}>{v}</li>
                        ))}
                      </ul>
                    </>
                  )}
                </div>
              )}
            </div>

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
