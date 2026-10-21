'use client';

import { useState } from 'react';
import {
  call,
  callText,
  type ApiOutcome,
  type AssessAdvisoryResult,
  type Exposure,
  type ImpactReport,
} from '../../lib/assuranceApi';
import { parseAdvisoryInput, type ParsedInput, type ParsedRecord } from '../../lib/advisoryInput';
import { Notice, Refusal, Skeleton } from './PanelFrame';
import { openedOrExisting, queueIds } from './caseIds';
import { API_BASE } from './usePanel';

type Source = { kind: 'pasted' } | { kind: 'file'; name: string } | { kind: 'hosted'; id: string };

const BASIS: Record<Exposure['basis'], string> = {
  hash: 'hash — confirmed: the artefact on the machine is byte-identical to one the supplier named',
  hash_mismatch:
    'hash mismatch — contradictory: neither affected nor clear (the label matches, the supplier’s own hashes do not)',
  version: 'version label — probable: rests on a label, and a label is not an artefact',
  name_only: 'component name only — possible: the version is unknown or not listed',
};

function distinct(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

// Where this input came from and what is, and is not, known about it. This page and the
// hosted API hold no supplier keys: nothing below says a signature was checked.
function Provenance({ parsed, source }: { parsed: Extract<ParsedInput, { ok: true }>; source: Source }) {
  const claims = parsed.records.map((r) => r.claims).filter((c): c is NonNullable<typeof c> => c !== null);
  if (claims.length === 0) {
    return (
      <div className="aw-prov" data-testid="adv-provenance">
        <p>
          <strong>Unsigned / unverified — local assessment.</strong> Nothing in this input identifies who issued it:{' '}
          <code>issued_by</code> is text the file asserts about itself.
        </p>
        <p>
          The impact check below is a local assessment of an advisory whose origin nobody has checked. If it came from
          a supplier, ask them for their signed feed and verify it yourself with{' '}
          <code>assurance supplier verify</code> before acting on it.
        </p>
      </div>
    );
  }
  const suppliers = distinct(claims.map((c) => c.supplierId));
  const legal = distinct(claims.map((c) => c.legalName));
  const prints = distinct(claims.map((c) => c.keyFingerprint));
  const contacts = distinct(claims.map((c) => c.keyContact));
  const signedCount = claims.filter((c) => c.hasSignature).length;
  return (
    <div className="aw-prov" data-testid="adv-provenance">
      <p>
        <strong>Signature not verified.</strong> {parsed.records.length} record(s) read; {signedCount} carry a signature
        field. The signature values were not checked, here or by the server.
      </p>
      <p>
        The file <em>claims</em> supplier <strong>{suppliers.join(', ') || 'none named'}</strong>
        {legal.length ? ` (${legal.join(', ')})` : ''} and signing key fingerprint{' '}
        {prints.length ? prints.map((p) => <code key={p}>{p} </code>) : <strong>none</strong>}.
        {prints.length > 1 && <strong> It names more than one key fingerprint.</strong>}
        {suppliers.length > 1 && <strong> It names more than one supplier.</strong>}
      </p>
      <p>
        This workspace and the hosted API hold no supplier keys and check no signatures, so a forged or edited record
        reads exactly like a genuine one here. To check a feed, run{' '}
        <code>assurance supplier verify --feed &lt;file&gt; --public-key &lt;supplier.pub&gt; --expect-supplier {suppliers[0] || '<id>'}</code>
        . Compare the fingerprint above with one the supplier gave you by another route
        {contacts.length ? <> (they say: {contacts.join('; ')})</> : ''} — not by a link in the advisory; a forged
        advisory carries its own key. Even a feed that passes that check shows only who signed and that nothing was
        altered, not that the advisories are correct, complete or timely.
      </p>
      {source.kind === 'hosted' && (
        <p>
          This copy is hosted by this service under account id <code>{source.id}</code>. On upload the host checks that
          a record parses, carries a non-empty signature and continues the chain (sequence, previous hash, one
          supplier). It does not check the signature against any key.
        </p>
      )}
    </div>
  );
}

function provenanceLine(parsed: Extract<ParsedInput, { ok: true }>, rec: ParsedRecord): string {
  if (!rec.claims) return 'Unsigned / unverified: this is a local assessment of an advisory whose origin nobody has checked.';
  return `Signature not verified: ${rec.claims.supplierId || 'an unnamed supplier'} is the file’s own claim (key ${rec.claims.keyFingerprint || 'not stated'}); this is a local assessment of an unverified record.`;
}

function ImpactResult({ report, parsed, rec }: { report: ImpactReport; parsed: Extract<ParsedInput, { ok: true }>; rec: ParsedRecord }) {
  const confirmed = report.exposures.filter((e) => e.basis === 'hash').length;
  const contradictory = report.exposures.filter((e) => e.basis === 'hash_mismatch').length;
  const byLabel = report.exposures.filter((e) => e.basis === 'version' || e.basis === 'name_only').length;
  const needs = report.exposures.filter((e) => e.needs_a_human).length;
  const verdictText =
    report.verdict === 'exposed'
      ? 'EXPOSED — standing safety evidence is now in question'
      : report.verdict === 'needs_review'
        ? 'NEEDS REVIEW — matches found, none with standing evidence'
        : 'No enrolled machine matches this advisory in its latest sealed manifest. That does not show that no machine is exposed: absence here is not evidence of safety.';
  return (
    <div data-testid="impact-result">
      <p className="aw-note" data-testid="impact-provenance">
        {provenanceLine(parsed, rec)}
      </p>
      {rec.withdrawnLater && (
        <Notice>
          This advisory is <strong>withdrawn later in this file</strong> (as the file says; that record is not verified
          either). Its supplier may no longer stand behind it.
        </Notice>
      )}
      <p className="aw-verdict" data-testid="impact-verdict">
        {report.advisory_id} ({report.issued_by}, {report.severity}) — {verdictText}
      </p>
      <p data-testid="impact-summary">
        {report.machines_affected.length} of {report.machines_in_fleet} machine(s) match · {confirmed} confirmed by hash
        · {contradictory} contradictory (neither affected nor clear, counted in neither column) · {byLabel} by label
        only · {needs} need a person · {report.functions_newly_in_question} safety function(s) newly in question.
        Counts are per machine and item. Assessed {report.assessed_at}.
      </p>
      {report.exposures.length > 0 && (
        <div className="aw-scroll">
          <table className="aw-table" data-testid="exposure-table">
            <thead>
              <tr>
                <th>Machine</th>
                <th>Item</th>
                <th>Match basis</th>
                <th>Safety functions</th>
              </tr>
            </thead>
            <tbody>
              {report.exposures.map((e, i) => (
                <tr key={`${e.machine}-${e.item_id}-${i}`} data-testid="exposure-row" data-machine={e.machine} data-basis={e.basis}>
                  <td>
                    {e.machine}
                    <br />
                    <span className="aw-note">{e.site || 'site not recorded'}</span>
                  </td>
                  <td>
                    {e.item_name} {e.item_version} <code>{e.item_id}</code>
                  </td>
                  <td>
                    <strong>{e.confidence}</strong> · {BASIS[e.basis]}
                    {e.needs_a_human && <strong className="aw-bad"> · needs a person</strong>}
                    <br />
                    <span className="aw-note">{e.detail}</span>
                  </td>
                  <td>
                    {e.functions.map((f) => (
                      <div key={f.function_id} data-testid="fn-row">
                        <strong>{f.function_id}</strong> {f.description}
                        {f.last_verified_at ? ` (verification evidence dated ${f.last_verified_at.slice(0, 10)})` : ''} —{' '}
                        {f.newly_in_question ? (
                          <strong className="aw-bad">now in question</strong>
                        ) : e.basis === 'hash_mismatch' ? (
                          <>unresolved (coverage: {f.coverage_before.replace(/_/g, ' ')})</>
                        ) : (
                          <>coverage already {f.coverage_before.replace(/_/g, ' ')}</>
                        )}
                      </div>
                    ))}
                    {e.functions.length === 0 && 'no safety function is credited to this item'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <h4>What this does not establish</h4>
      <ul data-testid="impact-skipped">
        {report.checks_skipped.map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ul>
    </div>
  );
}

export default function AdvisoriesPanel({
  apiKey,
  actor,
  setActor,
  onOpenCase,
  onChanged,
}: {
  apiKey: string;
  actor: string;
  setActor: (v: string) => void;
  onOpenCase: (caseId: string) => void;
  onChanged: () => void;
}) {
  const [text, setText] = useState('');
  const [hostedId, setHostedId] = useState('');
  const [source, setSource] = useState<Source>({ kind: 'pasted' });
  const [parsed, setParsed] = useState<ParsedInput | null>(null);
  const [notice, setNotice] = useState('');
  const [hostedOut, setHostedOut] = useState<ApiOutcome<string> | null>(null);
  const [selected, setSelected] = useState<ParsedRecord | null>(null);
  const [impact, setImpact] = useState<ApiOutcome<ImpactReport> | null>(null);
  const [checking, setChecking] = useState(false);
  const [caseOut, setCaseOut] = useState<ApiOutcome<AssessAdvisoryResult> | null>(null);
  const [opening, setOpening] = useState(false);
  const [confirmWithdrawn, setConfirmWithdrawn] = useState(false);
  const [existing, setExisting] = useState<Set<string> | null>(null);

  const reset = () => {
    setSelected(null);
    setImpact(null);
    setCaseOut(null);
    setNotice('');
    setHostedOut(null);
    setConfirmWithdrawn(false);
  };

  const read = (input: string, from: Source) => {
    reset();
    const p = parseAdvisoryInput(input);
    setSource(from);
    setParsed(p);
  };

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    const body = await file.text();
    setText(body);
    read(body, { kind: 'file', name: file.name });
  };

  const loadHosted = async () => {
    reset();
    const id = hostedId.trim();
    if (!id) {
      setParsed(null);
      setNotice('Enter the account id the supplier’s feed is hosted under.');
      return;
    }
    const out = await callText(API_BASE, `/v1/supplier/feed/${encodeURIComponent(id)}`);
    if (out.kind !== 'ok') {
      setParsed(null);
      setHostedOut(out);
      return;
    }
    setText(out.data);
    read(out.data, { kind: 'hosted', id });
  };

  const check = async (rec: ParsedRecord) => {
    setSelected(rec);
    setImpact(null);
    setCaseOut(null);
    setConfirmWithdrawn(false);
    setChecking(true);
    setImpact(await call<ImpactReport>(API_BASE, apiKey, '/v1/fleet/advisory', { method: 'POST', body: { advisory: rec.advisory } }));
    setChecking(false);
  };

  const openCase = async () => {
    if (!selected) return;
    if (!actor.trim()) {
      setCaseOut(null);
      setNotice('Enter the name of the person opening this case — it is recorded on the case.');
      return;
    }
    setNotice('');
    setOpening(true);
    const before = await queueIds(apiKey);
    setExisting(before);
    const out = await call<AssessAdvisoryResult>(API_BASE, apiKey, '/v1/change/assess/advisory', {
      method: 'POST',
      body: { advisory: selected.advisory, actor: actor.trim() },
    });
    setOpening(false);
    setCaseOut(out);
    if (out.kind === 'ok' && out.data.opened) onChanged();
  };

  const impactOk = impact?.kind === 'ok' ? impact.data : null;
  const parsedOk = parsed && parsed.ok ? parsed : null;

  return (
    <section id="aw-advisories" aria-labelledby="aw-advisories-h">
      <h2 id="aw-advisories-h">Supplier advisories and fleet impact</h2>
      <p className="aw-note">
        Paste or choose an advisory, a signed record or a supplier feed, and see which of your enrolled machines and
        safety functions it reaches, using the same engine as <code>assurance fleet advisory</code>. This page shows where
        the file came from as the file states it. It cannot confirm who issued it: signatures are checked with{' '}
        <code>assurance supplier verify</code>, against a key you hold.
      </p>
      <label className="aw-field">
        Advisory or feed (JSON; a feed is one record per line)
        <textarea className="aw-textarea" rows={6} value={text} onChange={(e) => setText(e.target.value)} />
      </label>
      <div className="aw-row">
        <button className="btn btn-outline" onClick={() => read(text, { kind: 'pasted' })}>
          Read advisory
        </button>
        <label>
          Choose an advisory or feed file
          <input type="file" accept=".json,.jsonl,.ndjson,application/json,text/plain" onChange={(e) => void onFile(e.target.files?.[0])} />
        </label>
      </div>
      <div className="aw-row">
        <label>
          Hosted feed (supplier account id)
          <input type="text" value={hostedId} onChange={(e) => setHostedId(e.target.value)} placeholder="acc_…" />
        </label>
        <button className="btn btn-outline" onClick={() => void loadHosted()} disabled={!API_BASE}>
          Load hosted feed
        </button>
      </div>
      <p className="aw-note">
        Hosted feeds are public to read. There is no directory of suppliers: you need the account id the supplier gave
        you.
      </p>

      {notice && <Notice>{notice}</Notice>}
      {hostedOut && hostedOut.kind !== 'ok' && (
        <Refusal
          outcome={hostedOut}
          what="Hosted feed"
          notFoundNote="That is not the same as a supplier with nothing to report: nothing was read, so nothing can be said about your fleet."
        />
      )}
      {parsed && !parsed.ok && <Notice>{parsed.error}</Notice>}

      {parsedOk && (
        <>
          <Provenance parsed={parsedOk} source={source} />
          <div className="aw-scroll">
            <table className="aw-table" data-testid="adv-records">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Advisory</th>
                  <th>Severity</th>
                  <th>Issued by (as stated)</th>
                  <th>In this file</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {parsedOk.records.map((r) => (
                  <tr
                    key={r.index}
                    data-testid="adv-record"
                    data-advisory-id={r.advisoryId}
                    data-withdrawal={r.isWithdrawal ? 'true' : 'false'}
                    className={selected?.index === r.index ? 'aw-selected' : ''}
                  >
                    <td>{r.claims?.sequence ?? r.index + 1}</td>
                    <td>
                      <strong>{r.advisoryId}</strong>
                      <br />
                      <span className="aw-note">{r.title}</span>
                    </td>
                    <td>{r.severity}</td>
                    <td>{r.issuedBy}</td>
                    <td>
                      {r.isWithdrawal
                        ? `withdrawal of ${r.withdraws}${r.withdrawalReason ? `: ${r.withdrawalReason}` : ''}`
                        : r.withdrawnLater
                          ? 'withdrawn later in this file'
                          : 'standing'}
                    </td>
                    <td>
                      {!r.isWithdrawal && (
                        <button className="btn btn-outline" disabled={checking} onClick={() => void check(r)}>
                          Check fleet impact
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {checking && <Skeleton what="the fleet impact" />}
      {impact && impact.kind !== 'ok' && <Refusal outcome={impact} what="Fleet impact" />}
      {impactOk && selected && parsedOk && <ImpactResult report={impactOk} parsed={parsedOk} rec={selected} />}

      {impactOk && selected && impactOk.verdict !== 'clear' && (
        <div className="aw-actions">
          <h4>Open an assurance case</h4>
          <p className="aw-note">
            Nothing has been opened. A case is a record that people must work: it lists the re-verification each
            affected function needs, and it can only be closed by a named person once evidence stands. It records the
            advisory&apos;s content hash and who opened it; it does not record a signature check, because none was made.
          </p>
          <label className="aw-field">
            Your name (recorded on the case)
            <input type="text" value={actor} onChange={(e) => setActor(e.target.value)} />
          </label>
          {selected.withdrawnLater && (
            <label className="aw-field">
              <input type="checkbox" checked={confirmWithdrawn} onChange={(e) => setConfirmWithdrawn(e.target.checked)} /> The
              file says this advisory was withdrawn; open a case on it anyway
            </label>
          )}
          <button
            className="btn btn-primary"
            disabled={opening || (selected.withdrawnLater && !confirmWithdrawn)}
            onClick={() => void openCase()}
          >
            Open assurance case
          </button>
        </div>
      )}
      {caseOut && caseOut.kind !== 'ok' && <Refusal outcome={caseOut} what="Open case" />}
      {caseOut?.kind === 'ok' && (
        <div className="aw-prov" role="status" data-testid="adv-case-result">
          {caseOut.data.opened && caseOut.data.case ? (
            <p>
              {openedOrExisting(existing, caseOut.data.case.case_id, caseOut.data.case.status)}{' '}
              <button className="aw-link" onClick={() => onOpenCase(caseOut.data.case!.case_id)}>
                Open case {caseOut.data.case.case_id}
              </button>
            </p>
          ) : (
            <p>No case opened: the assessment found no match to work (verdict {caseOut.data.verdict}).</p>
          )}
        </div>
      )}
    </section>
  );
}
