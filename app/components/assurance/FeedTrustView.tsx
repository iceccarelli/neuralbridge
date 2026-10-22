'use client';

import { useState } from 'react';
import {
  call,
  type ApiOutcome,
  type AssessAdvisoryResult,
  type FeedTrust,
  type SignedImpactResult,
  type TrustedAdvisoryRow,
} from '../../lib/assuranceApi';
import { ClassificationTable } from './ImpactParts';
import { Notice, Refusal } from './PanelFrame';
import { API_BASE } from './usePanel';

// What each state means, in the words the policy uses. There is no single "verified" badge: a feed
// is judged on separate questions and every one is shown on its own.
const SIGNATURE_STATE: Record<string, string> = {
  all_valid:
    'every record’s signature checks out under the key it was checked against (a pinned key, or a candidate key you supplied and have NOT pinned)',
  some_invalid:
    'at least one signature FAILS or is malformed — evidence of tampering or damage, not an inability to check',
  not_checkable: 'no signature could be checked: no pinned key covers these records',
  none: 'no records',
};
const KEY_STATE: Record<string, string> = {
  pinned: 'every record is signed by a key pinned for this supplier and in force on its publication date',
  unknown_key: 'a record is signed by a key you have not pinned — not trusted',
  wrong_supplier: 'a record is signed by a key pinned for a different supplier — not trusted',
  revoked: 'a record is signed by a revoked key — not trusted',
  retired: 'a record is signed by a key that was retired before it was published — not trusted',
  not_yet_effective: 'a record is signed by a key that was not yet in force when it was published — not trusted',
  store_unhealthy: 'the trust store itself does not check out, so no key can be relied on',
  none: 'no records',
};

function Row({ id, name, value, note }: { id: string; name: string; value: string; note: string }) {
  return (
    <tr data-testid={id} data-value={value}>
      <th scope="row">{name}</th>
      <td>
        <code>{value}</code>
      </td>
      <td>{note}</td>
    </tr>
  );
}

export function FeedStates({ t }: { t: FeedTrust }) {
  const dupes = t.duplicate_advisories;
  const conflicts = t.conflicting_advisories;
  return (
    <div data-testid="feed-trust">
      <div className="aw-scroll">
        <table className="aw-table" data-testid="feed-states">
          <thead>
            <tr>
              <th>Question</th>
              <th>Answer</th>
              <th>What it means</th>
            </tr>
          </thead>
          <tbody>
            <Row
              id="state-readable"
              name="Structurally readable"
              value={t.structurally_readable ? 'yes' : 'no'}
              note={
                t.structurally_readable
                  ? `${t.record_count} record(s) parse. Readable says nothing about who wrote them.`
                  : 'The feed does not parse into records.'
              }
            />
            <Row
              id="state-signature"
              name="Signature state"
              value={t.signature_state}
              note={SIGNATURE_STATE[t.signature_state] ?? ''}
            />
            <Row
              id="state-key-trust"
              name="Key-trust state"
              value={t.key_trust_state}
              note={KEY_STATE[t.key_trust_state] ?? ''}
            />
            <Row
              id="state-chain"
              name="Chain valid"
              value={t.chain_valid ? 'yes' : 'no'}
              note={
                t.chain_valid
                  ? 'Records are in sequence and each names its predecessor.'
                  : `Broken: ${t.chain_problems[0] ?? 'see the problems below'}. A record may have been removed, duplicated or reordered.`
              }
            />
            <Row
              id="state-dup-conflict"
              name="Duplicates and conflicts"
              value={`${dupes.length} duplicate / ${conflicts.length} conflicting`}
              note={
                conflicts.length
                  ? `CONFLICT: ${conflicts.join(', ')} appear with different content under one id. Two statements under one identity.`
                  : dupes.length
                    ? `${dupes.join(', ')} published again with identical content.`
                    : 'None.'
              }
            />
            <Row
              id="state-withdrawals"
              name="Withdrawals"
              value={`${t.withdrawn.length} applied / ${t.unauthenticated_withdrawals.length} not applied`}
              note={
                (t.withdrawn.length
                  ? `Withdrawn by a signed record under a pinned key: ${t.withdrawn.join(', ')}. `
                  : '') +
                (t.unauthenticated_withdrawals.length
                  ? `NOT applied (the withdrawing record is not trusted, and an untrusted retraction must not cancel an advisory): ${t.unauthenticated_withdrawals.join(', ')}.`
                  : '') +
                (!t.withdrawn.length && !t.unauthenticated_withdrawals.length ? 'None in this feed.' : '')
              }
            />
            <Row
              id="state-policy"
              name="Policy"
              value={t.policy_satisfied ? 'met' : 'not met'}
              note={`Summary: ${t.trust_state}. Met only when every question above is answered well. It is a summary of those answers, never a substitute for them.`}
            />
          </tbody>
        </table>
      </div>
      <p className="aw-note">
        Supplier <strong>{t.supplier_id || 'none named'}</strong>; key fingerprint(s){' '}
        {t.key_fingerprints.length ? t.key_fingerprints.map((f) => <code key={f}>{f} </code>) : 'none'}
      </p>
      {t.records.length > 0 && (
        <details>
          <summary>Per record: signature and key state</summary>
          <div className="aw-scroll">
            <table className="aw-table" data-testid="record-trust-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Advisory</th>
                  <th>Key</th>
                  <th>Signature</th>
                  <th>Key trust</th>
                </tr>
              </thead>
              <tbody>
                {t.records.map((r) => (
                  <tr
                    key={r.sequence}
                    data-testid="record-trust-row"
                    data-signature={r.signature}
                    data-key-trust={r.key_trust}
                  >
                    <td>{r.sequence}</td>
                    <td>
                      {r.advisory_id}
                      {r.is_withdrawal ? ' (withdrawal)' : ''}
                    </td>
                    <td>
                      <code>{r.key_fingerprint}</code>
                    </td>
                    <td>
                      {r.signature}
                      {r.signature_valid_under_candidate !== null && r.signature_valid_under_candidate !== undefined
                        ? ` (under your candidate key: ${r.signature_valid_under_candidate ? 'checks out' : 'fails'} — that key is not pinned, so this is not trust)`
                        : ''}
                    </td>
                    <td>{r.key_trust.replace(/_/g, ' ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
      {t.problems.length > 0 && (
        <details open>
          <summary>Problems the evaluation found ({t.problems.length})</summary>
          <ul data-testid="feed-problems">
            {t.problems.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

export function TrustBasis({ row }: { row: TrustedAdvisoryRow }) {
  if (row.automated_consequences_permitted && row.trust_basis === 'manual_override' && row.override) {
    return (
      <p className="aw-prov" data-testid="trust-basis" data-basis="manual_override">
        <strong>Attributed manual override — not trust in the feed.</strong> Accepted by{' '}
        <strong>{row.override.actor}</strong> at {row.override.at}: {row.override.reason}. Bound to this advisory&apos;s
        content hash <code>{row.override.advisory_hash.slice(0, 12)}</code>; a changed advisory is not covered. The feed
        itself still does not meet policy.
      </p>
    );
  }
  if (row.automated_consequences_permitted) {
    return (
      <p className="aw-prov" data-testid="trust-basis" data-basis={row.trust_basis}>
        <strong>Trusted consequences permitted</strong> — basis <code>{row.trust_basis}</code>: the feed meets policy
        under keys you pinned. That shows who signed these bytes, not that the advisory is correct, complete or timely.
      </p>
    );
  }
  return (
    <p className="aw-alert" data-testid="trust-basis" data-basis="none">
      <strong>NOT TRUSTED — INSPECT ONLY. No trusted consequences.</strong> Nothing automated may follow from this
      advisory, and no case is opened from it here unless a person overrides it, on the record.
      {row.override_refused && (
        <span className="aw-remedy" data-testid="override-refused">
          It cannot be overridden: {row.override_refused}.
        </span>
      )}
    </p>
  );
}

function OverrideForm({
  apiKey,
  row,
  feedBody,
  actor,
  setActor,
  onDone,
}: {
  apiKey: string;
  row: TrustedAdvisoryRow;
  feedBody: Record<string, string>;
  actor: string;
  setActor: (v: string) => void;
  onDone: () => void;
}) {
  const [reason, setReason] = useState('');
  const [notice, setNotice] = useState('');
  const [out, setOut] = useState<ApiOutcome<unknown> | null>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const submit = async () => {
    setNotice('');
    setOut(null);
    if (!actor.trim() || !reason.trim()) {
      setNotice('An override needs your name and a reason. It is recorded in your ledger under both.');
      return;
    }
    setBusy(true);
    const res = await call<unknown>(API_BASE, apiKey, '/v1/supplier/trust/override', {
      method: 'POST',
      body: {
        ...feedBody,
        advisory_id: row.advisory_id,
        actor: actor.trim(),
        reason: reason.trim(),
      },
    });
    setBusy(false);
    setOut(res);
    if (res.kind === 'ok') onDone();
  };
  return (
    <>
      {
        <div data-testid="override-flow">
          {!open ? (
            <button className="btn btn-outline" onClick={() => setOpen(true)}>
              Override: accept this one advisory anyway…
            </button>
          ) : (
            <div className="aw-actions">
              <h4>Manual override of {row.advisory_id}</h4>
              <p className="aw-note">
                This accepts ONE advisory from a feed that did not meet policy. It is recorded in your ledger as an
                override by the name below, with your reason, bound to the advisory&apos;s content hash. It does not
                make the feed trusted, does not pin the key, and is the person&apos;s decision, not a signature check.
              </p>
              <label className="aw-field">
                Your name (recorded; declared, not authenticated)
                <input type="text" value={actor} onChange={(e) => setActor(e.target.value)} name="override-actor" />
              </label>
              <label className="aw-field">
                Why accept it
                <textarea
                  className="aw-textarea"
                  rows={2}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  name="override-reason"
                />
              </label>
              <button className="btn btn-primary" disabled={busy} onClick={() => void submit()}>
                Record override
              </button>
              {notice && <Notice>{notice}</Notice>}
              {out && out.kind !== 'ok' && <Refusal outcome={out} what="Override" />}
            </div>
          )}
        </div>
      }
    </>
  );
}

export default function SignedResult({
  result,
  apiKey,
  feedBody,
  actor,
  setActor,
  advisoryFor,
  onOpenCase,
  onChanged,
  onRerun,
}: {
  result: SignedImpactResult;
  apiKey: string;
  feedBody: Record<string, string>;
  actor: string;
  setActor: (v: string) => void;
  advisoryFor: (advisoryId: string) => Record<string, unknown> | null;
  onOpenCase: (caseId: string) => void;
  onChanged: () => void;
  onRerun: () => void;
}) {
  const t = result.trust;
  const [caseOut, setCaseOut] = useState<Record<string, ApiOutcome<AssessAdvisoryResult>>>({});
  const [notice, setNotice] = useState('');
  const [opening, setOpening] = useState('');

  const openCase = async (row: TrustedAdvisoryRow) => {
    setNotice('');
    if (!row.automated_consequences_permitted) return; // the button is disabled; this is a second lock
    const advisory = advisoryFor(row.advisory_id);
    if (!advisory) {
      setNotice(`The advisory body for ${row.advisory_id} could not be found in the text read.`);
      return;
    }
    if (!actor.trim()) {
      setNotice('Enter the name of the person opening this case — it is recorded on the case.');
      return;
    }
    setOpening(row.advisory_id);
    const out = await call<AssessAdvisoryResult>(API_BASE, apiKey, '/v1/change/assess/advisory', {
      method: 'POST',
      body: { advisory, actor: actor.trim() },
    });
    setOpening('');
    setCaseOut({ ...caseOut, [row.advisory_id]: out });
    if (out.kind === 'ok' && out.data.opened) onChanged();
  };

  return (
    <>
      <div data-testid="signed-result" data-inspect-only={result.inspect_only ? 'true' : 'false'}>
        <h3>Trust evaluation of this feed, under the keys you pinned</h3>
        {result.inspect_only ? (
          <p className="aw-alert" role="alert" data-testid="inspect-only-banner">
            <strong>INSPECT ONLY — no trusted consequences.</strong> No advisory in this feed carries trust. You can
            read what each one would touch, but nothing here may open a case or stop a machine on the strength of this
            feed.
          </p>
        ) : (
          <p className="aw-prov" data-testid="trusted-banner">
            <strong>At least one advisory here carries trusted consequences</strong> (see each advisory&apos;s basis).
            Any others in the feed are still inspect-only.
          </p>
        )}
        <p className="aw-note" data-testid="trust-statement">
          {result.trust_statement}
        </p>
        <FeedStates t={t} />
        {notice && <Notice>{notice}</Notice>}
        {result.advisories.length === 0 && (
          <p className="aw-note">
            No standing advisory was assessed (every advisory is withdrawn, or the feed is empty or unreadable).
          </p>
        )}
        {result.advisories.map((a) => {
          const co = caseOut[a.advisory_id];
          return (
            <div
              key={a.advisory_id}
              className="aw-detail"
              data-testid="trust-advisory"
              data-advisory-id={a.advisory_id}
              data-permitted={a.automated_consequences_permitted ? 'true' : 'false'}
            >
              <h4>
                {a.advisory_id} — {a.title || 'untitled'} ({a.severity || 'severity not stated'}), record {a.sequence}
              </h4>
              <TrustBasis row={a} />
              {a.impact ? (
                <>
                  <p data-testid="signed-impact-summary">
                    Impact
                    {a.automated_consequences_permitted ? '' : ' (inspect only)'}: verdict{' '}
                    <strong>{a.impact.verdict}</strong> · {a.impact.machines_affected.length} of{' '}
                    {a.impact.machines_in_fleet} machine(s) match · {a.impact.functions_newly_in_question} safety
                    function(s) newly in question. Assessed {a.impact.assessed_at}.
                  </p>
                  <ClassificationTable report={a.impact} />
                  <h5>What this does not establish</h5>
                  <ul>
                    {a.impact.checks_skipped.map((s) => (
                      <li key={s}>{s}</li>
                    ))}
                  </ul>
                </>
              ) : (
                <Notice>
                  The impact of {a.advisory_id} could not be assessed
                  {a.error ? `: ${a.error}` : ''}. That is not a clear result.
                </Notice>
              )}
              <div className="aw-actions">
                <button
                  className="btn btn-primary"
                  disabled={
                    !a.automated_consequences_permitted ||
                    opening === a.advisory_id ||
                    !a.impact ||
                    a.impact.exposures.length === 0
                  }
                  title={
                    a.automated_consequences_permitted
                      ? undefined
                      : 'Disabled: this advisory is not trusted (inspect only). The server did not permit automated consequences.'
                  }
                  onClick={() => void openCase(a)}
                >
                  Open assurance case from {a.advisory_id}
                </button>
                {!a.automated_consequences_permitted && (
                  <span className="aw-note" data-testid="case-disabled-why">
                    {' '}
                    Disabled: the server did not permit automated consequences for this advisory.
                  </span>
                )}
                {a.automated_consequences_permitted && a.impact && a.impact.exposures.length === 0 && (
                  <span className="aw-note"> Nothing matched, so there is no case to open.</span>
                )}
                {a.automated_consequences_permitted && (
                  <p className="aw-note">
                    The case is opened from the advisory&apos;s content and records who opened it. The case route is not
                    told this feed&apos;s trust state; that is why it is offered only where the server permitted it.
                  </p>
                )}
                {!a.automated_consequences_permitted && !a.override_refused && (
                  <OverrideForm
                    apiKey={apiKey}
                    row={a}
                    feedBody={feedBody}
                    actor={actor}
                    setActor={setActor}
                    onDone={onRerun}
                  />
                )}
              </div>
              {co && co.kind !== 'ok' && <Refusal outcome={co} what="Open case" />}
              {co?.kind === 'ok' && (
                <div className="aw-prov" role="status" data-testid="signed-case-result">
                  {co.data.opened && co.data.case ? (
                    <p>
                      Case {co.data.case.case_id} is {co.data.case.status}.{' '}
                      <button className="aw-link" onClick={() => onOpenCase(co.data.case!.case_id)}>
                        Open case {co.data.case.case_id}
                      </button>
                    </p>
                  ) : (
                    <p>No case opened: the assessment found no match to work (verdict {co.data.verdict}).</p>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </>
  );
}
