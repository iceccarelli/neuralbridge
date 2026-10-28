'use client';

import { useState } from 'react';
import {
  call,
  explainForbidden,
  parseAttribution,
  type ApiOutcome,
  type Attribution,
  type CaseDetail,
  type ExportBundle,
  type ExportCompleteness,
  exportCompleteness,
  type HistoryItem,
  type Replay,
} from '../../lib/assuranceApi';
import DecisionCredential, { useOperatorKey } from './DecisionCredential';
import { Notice, PanelFrame, Refusal } from './PanelFrame';
import { API_BASE, usePanel } from './usePanel';

type Who = { text: string; title: string; attribution: Attribution };

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
    // The basis is read from the role string sealed with the entry. An entry that does not carry one
    // (written before attribution was recorded) says so; it is never upgraded to "authenticated".
    const attribution = parseAttribution(a?.role);
    if (!name) return { text: 'not recorded', title: '', attribution };
    return { text: `${name} (${a?.kind || 'actor'})`, title: a?.role || '', attribution };
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

// The sentence the server gives (blocked_reason.message) when a submission was recorded but cleared nothing.
function blockedMessage(data: unknown): string {
  const reason = (data as { blocked_reason?: { message?: unknown } } | null)?.blocked_reason;
  return typeof reason?.message === 'string' ? reason.message : '';
}

// Four things a hosted export can be, driven by the response. The wording never promises more
// than the file carries: a ticked box is a request, and the server may have declined it
// (`skeleton_truncated`), and a hosted export has no signed anchor until the operator has signed
// the account's ledger.
export function completenessNote(c: ExportCompleteness): string {
  const a = c.anchor;
  const anchorLine = !a
    ? 'It carries no signed anchor: the operator has not signed this ledger, so no signature fixes how far it reached.'
    : a.readFromLedger
      ? `It carries a signed anchor (attestation ${a.sequence}, head seq ${a.headSeq}, read from your ledger); records after that head are covered by no signature.`
      : `It carries an attestation (${a.sequence}) the signer did not read from your ledger, which is not a completeness check.`;
  if (c.skeleton === 'carried') {
    return a && a.readFromLedger
      ? `This file carries the skeleton and a signed anchor (attestation ${a.sequence}, head seq ${a.headSeq}, read from your ledger), so with the signer’s public key the check can show that none of this case’s records was removed up to that head. Records after it are covered by no signature.`
      : `This file carries the skeleton, but it does not by itself show that none of this case’s records was removed: ${anchorLine} Without a signed head the check reports completeness as not checked (a record cut from the end, or a rebuilt chain, would read the same). Download it again once the operator has signed your ledger.`;
  }
  if (c.skeleton === 'truncated') {
    return `The server left the skeleton out because your ledger holds too many other entries to list (skeleton_truncated), so this file names no other case and cannot show that none of this case’s records was removed, with or without the signer’s key: completeness is reported as not established. ${anchorLine}`;
  }
  const why =
    c.skeleton === 'absent'
      ? 'You asked for the skeleton but the server did not return one, so this file names no other case'
      : 'This file names no other case';
  return `${why} and cannot show that none of this case’s records was removed: the check reports completeness as not checked, and with the signer’s public key it reports that completeness could not be established. ${anchorLine} Download it again with the skeleton to have that checked.`;
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
  const [exported, setExported] = useState<{ file: string; entries: number; completeness: ExportCompleteness } | null>(null);
  // Off by default: the skeleton names every OTHER entry's id, kind and time in this ledger.
  const [withSkeleton, setWithSkeleton] = useState(false);
  const [busy, setBusy] = useState(false);
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState('');
  const [entry, setEntry] = useState('');
  const [waiver, setWaiver] = useState('');
  const [resumeWhy, setResumeWhy] = useState('');
  const [replay, setReplay] = useState<ApiOutcome<Replay> | null>(null);
  const [replaying, setReplaying] = useState(false);
  const [opKey, setOpKey] = useOperatorKey();
  // Which action the last answer belongs to, so a refusal is shown beside the action refused.
  const [resultAt, setResultAt] = useState('');

  const runReplay = async () => {
    setReplay(null);
    setReplaying(true);
    setReplay(await call<Replay>(API_BASE, apiKey, `/v1/change/cases/${enc}/replay`));
    setReplaying(false);
  };

  // `human` steps (decision, resume, resolve-decision, waive-reverification) go only with the
  // decision credential; the server refuses an account key for them, so none is sent. For the other
  // steps an operator key, when entered, attributes the action server-side and no name is sent.
  const act = async (path: string, body: Record<string, unknown>, human = false) => {
    setResult(null);
    setNotice('');
    setResultAt(path);
    if (human && !opKey.trim()) {
      setNotice(
        'This step is a human decision and needs a decision credential: the key of an operator with the decider role. Enter it in the Decision credential section, or create the first operator there. Nothing was sent.',
      );
      return;
    }
    const useOp = !!opKey.trim();
    if (!useOp && !actor.trim()) {
      setNotice('Enter the name of the person taking this action — it is recorded as declared, not authenticated.');
      return;
    }
    setBusy(true);
    const out = await call<unknown>(API_BASE, useOp ? opKey.trim() : apiKey, `/v1/change/cases/${enc}/${path}`, {
      method: 'POST',
      body: useOp ? body : { ...body, actor: actor.trim() },
    });
    setBusy(false);
    setResult(out);
    if (out.kind === 'ok') {
      await Promise.all([detail.reload(), bundle.reload()]);
      onChanged();
    }
  };

  // Where a refusal of the action `at` is shown: next to that action, with the server's own reason
  // and, for a 403 it has a code for, what the person can do about it.
  const refusal = (at: string) => {
    if (!result || result.kind === 'ok' || resultAt !== at) return null;
    const hint = result.kind === 'forbidden' ? explainForbidden(result) : '';
    return (
      <div data-testid="action-refusal" data-outcome={result.kind} data-code={result.kind === 'forbidden' ? (result.code ?? '') : ''}>
        <Refusal outcome={result} what="Action" />
        {hint && <p className="aw-note">{hint}</p>}
        {result.kind === 'conflict' && (
          <p className="aw-note">The server refused this and changed nothing. The reason above is the server&apos;s own.</p>
        )}
      </div>
    );
  };

  const download = async () => {
    setExported(null);
    setNotice('');
    setResult(null);
    setResultAt('export');
    const skeleton = withSkeleton;
    const out = await call<ExportBundle>(
      API_BASE,
      apiKey,
      `/v1/change/cases/${enc}/export${skeleton ? '?skeleton=true' : ''}`,
    );
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
    const file = skeleton ? `case-${caseId}-with-skeleton.json` : `case-${caseId}.json`;
    a.download = file;
    a.click();
    URL.revokeObjectURL(url);
    // What the FILE carries comes from the response, not from the box that was ticked.
    setExported({ file, entries: out.data.entries.length, completeness: exportCompleteness(out.data, skeleton) });
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
        // Entries a submission was recorded for but could not clear because the evidence is under the floor.
        const belowFloor = c.required_reverifications.filter((e) => (c.evidence_current[e] ?? '').startsWith('below_validated'));
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
                {belowFloor.length > 0 && (
                  <p className="aw-note" data-testid="reverify-blocked">
                    Not cleared: {belowFloor.join(', ')} — the evidence is below the &lsquo;validated&rsquo; floor. A
                    declared provenance is capped at &lsquo;community&rsquo;; &lsquo;validated&rsquo; needs a recorder
                    attestation accepted under the verifier&apos;s own trust list. A decider operator may waive the
                    entry; a waiver is recorded as a waiver and never reads as current.
                  </p>
                )}
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
                  reads &ldquo;waived&rdquo;. A verification reaches &lsquo;validated&rsquo; only if a recorder attestation
                  of its trace is accepted under the verifier&apos;s own trust list (a declared provenance is capped at
                  &lsquo;community&rsquo;); otherwise a submission is recorded but a required entry is closed only by
                  a decider&apos;s waiver.
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
                      <td data-testid="history-who" title={who?.[i]?.title} data-attribution={who?.[i]?.attribution.basis}>
                        {who ? (
                          <>
                            {who[i].text}
                            <br />
                            <span
                              className={who[i].attribution.basis === 'authenticated_operator' ? 'aw-note' : 'aw-note aw-bad'}
                              data-testid="history-attribution"
                            >
                              {who[i].attribution.label}
                            </span>
                          </>
                        ) : whoPending ? (
                          'loading…'
                        ) : (
                          'not available — the evidence export that carries it was not received'
                        )}
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
              &ldquo;Who&rdquo; is the name sealed on that step&apos;s ledger entry, with the basis it was sealed under.
              &ldquo;Operator credential presented&rdquo; means a key issued to that named operator was used; &ldquo;name
              declared&rdquo; means whoever held the account key typed it. Neither is identity proof. An entry that does
              not record a basis says &ldquo;attribution not recorded&rdquo;; older entries are not upgraded.
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
                <DecisionCredential apiKey={apiKey} opKey={opKey} setOpKey={setOpKey} />
                <label>
                  Why resume
                  <textarea rows={2} value={resumeWhy} onChange={(e) => setResumeWhy(e.target.value)} />
                </label>
                <button
                  className="btn btn-outline"
                  disabled={busy}
                  onClick={() => {
                    if (!resumeWhy.trim()) {
                      setResult(null);
                      setNotice('Resuming a case needs a reason.');
                      return;
                    }
                    void act('resume', { reason: resumeWhy.trim() }, true);
                  }}
                >
                  Resume case
                </button>
                {refusal('resume')}
              </div>
            )}
            {!settled && !deferred && (
              <div className="aw-actions">
                <h4>Actions</h4>
                <DecisionCredential apiKey={apiKey} opKey={opKey} setOpKey={setOpKey} />
                <label>
                  Your name
                  <input value={actor} onChange={(e) => setActor(e.target.value)} />
                </label>
                <p className="aw-note" data-testid="attribution-note">
                  {opKey.trim()
                    ? 'The operator key above attributes claim, advance and re-verification to that operator; the name field is not sent.'
                    : 'Without an operator key, claim, advance and re-verification are recorded under the name you declare, marked as declared by the account key. That is not authentication.'}
                </p>
                <div className="aw-row">
                  <label>
                    Owner
                    <input value={owner} onChange={(e) => setOwner(e.target.value)} />
                  </label>
                  <button
                    className="btn btn-outline"
                    disabled={busy}
                    onClick={() => owner.trim() && void act('claim', { owner: owner.trim() })}
                  >
                    Claim
                  </button>
                  <button className="btn btn-outline" disabled={busy} onClick={() => void act('advance', {})}>
                    Advance
                  </button>
                </div>
                {refusal('claim')}
                {refusal('advance')}
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
                      });
                    }}
                  >
                    Submit
                  </button>
                  {refusal('reverification')}
                  {result?.kind === 'ok' && resultAt === 'reverification' && blockedMessage(result.data) && (
                    <p className="aw-note" role="status" data-testid="reverify-blocked-reason">
                      Recorded, but the case is still waiting: {blockedMessage(result.data)}
                    </p>
                  )}
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
                        if (!answer.trim()) {
                          setResult(null);
                          setNotice('An answer needs the decision the person actually made.');
                          return;
                        }
                        void act('resolve-decision', {
                          decision: c.human_decisions_required.includes(question) ? question : c.human_decisions_required[0],
                          resolution: answer.trim(),
                        }, true);
                      }}
                    >
                      Record answer
                    </button>
                    {refusal('resolve-decision')}
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
                        if (!waiver.trim()) {
                          setResult(null);
                          setNotice('A waiver needs a reason: why closing without evidence is acceptable.');
                          return;
                        }
                        void act('waive-reverification', {
                          entry: c.required_reverifications.includes(entry) ? entry : c.required_reverifications[0],
                          reason: waiver.trim(),
                        }, true);
                      }}
                    >
                      Waive without evidence
                    </button>
                    {refusal('waive-reverification')}
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
                        if (!reason.trim()) {
                          setResult(null);
                          setNotice('A decision needs a reason.');
                          return;
                        }
                        void act('decision', { disposition: d, reason: reason.trim() }, true);
                      }}
                    >
                      {d === 'closed' ? 'Close' : d === 'deferred' ? 'Defer' : 'Reject'}
                    </button>
                  ))}
                </div>
                {refusal('decision')}
                <p className="aw-note">
                  The server decides whether a case may close: it refuses until the underlying evidence is current and
                  every human question is answered, whatever this page sends.
                </p>
              </div>
            )}
            {notice && <Notice>{notice}</Notice>}
            {refusal('export')}

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
              <label className="aw-note" style={{ display: 'block', marginBottom: '0.5rem' }}>
                <input
                  type="checkbox"
                  data-testid="export-skeleton"
                  checked={withSkeleton}
                  onChange={(e) => setWithSkeleton(e.target.checked)}
                />{' '}
                Include the ledger skeleton, so the file&apos;s completeness can be checked
              </label>
              <p className="aw-note" data-testid="export-skeleton-note">
                The skeleton lists the <strong>id, kind and time of every other entry in your ledger</strong> &mdash; your
                other cases and incidents &mdash; with no evidence in them. It is what lets a verifier see that a record of
                this case was removed. Leave it off unless the person who receives the file may see those ids.
              </p>
              <button className="btn btn-secondary" onClick={() => void download()}>
                Download this case&apos;s evidence{withSkeleton ? ' (with skeleton)' : ''}
              </button>{' '}
              <a href="/verify">Verify this export</a>
              {exported && (
                <p data-testid="export-done">
                  Saved <code>{exported.file}</code> ({exported.entries} ledger entries; the server reported the chain as
                  verified when it built the file). Anyone can check it offline, without an account:{' '}
                  <code>python -m assurance evidence verify {exported.file}</code>. That shows the file is internally
                  consistent: every record still matches its hash. A rebuilt chain would read the same, and it does not
                  show that the file matches the ledger as held; for that, check a signed head attestation.{' '}
                  <span data-testid="export-completeness" data-skeleton={exported.completeness.skeleton} data-anchor={exported.completeness.anchor ? 'present' : 'absent'}>
                    {completenessNote(exported.completeness)}
                  </span>{' '}
                  If the server refuses the export as contradicting a signed head it read from your ledger, keep the
                  ledger and its attestation log as they are.
                </p>
              )}
              {!exported && (
                <p className="aw-note">
                  The offline check shows an export is internally consistent: every record still matches its hash. It does
                  not show that the export matches the ledger as held; that needs a signed head attestation. Without the
                  skeleton this download names no other case, so completeness is reported as not checked, and as not
                  established when you check it against a signed head.
                </p>
              )}
            </div>
          </div>
        );
      }}
    </PanelFrame>
  );
}
