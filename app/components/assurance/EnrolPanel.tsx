'use client';

import { useEffect, useRef, useState } from 'react';
import { actorProblem, call, receiptOf, type ApiOutcome, type EnrolReceipt } from '../../lib/assuranceApi';
import EnrolReceiptView from './EnrolReceiptView';
import { Notice, Refusal } from './PanelFrame';
import { API_BASE } from './usePanel';

// POST /v1/machinery/enrol. The manifest and the named person's declaration go to the server;
// the receipt that comes back is shown as written. Enrolment records who declared which
// machine and configuration. It runs no verification and this panel never says otherwise.
export default function EnrolPanel({
  apiKey,
  actor,
  setActor,
  onChanged,
}: {
  apiKey: string;
  actor: string;
  setActor: (v: string) => void;
  onChanged: () => void;
}) {
  const [manifest, setManifest] = useState('');
  const [fileName, setFileName] = useState('');
  const [site, setSite] = useState('');
  const [owner, setOwner] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [out, setOut] = useState<ApiOutcome<EnrolReceipt> | null>(null);
  const result = useRef<HTMLDivElement>(null);

  // Move focus to the answer so a keyboard or screen-reader user lands on it.
  useEffect(() => {
    if (out || notice) result.current?.focus();
  }, [out, notice]);

  const readFile = async (file: File | undefined) => {
    if (!file) return;
    setFileName(file.name);
    setManifest(await file.text());
  };

  const run = async () => {
    setNotice('');
    setOut(null);
    if (!API_BASE || !apiKey) {
      setNotice('Paste an API key first.');
      return;
    }
    const problem = actorProblem(actor);
    if (problem) {
      setNotice(problem);
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(manifest);
    } catch {
      setNotice('That manifest is not valid JSON.');
      return;
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      setNotice('A manifest is one JSON object describing one machine.');
      return;
    }
    setBusy(true);
    const res = await call<EnrolReceipt>(API_BASE, apiKey, '/v1/machinery/enrol', {
      method: 'POST',
      body: {
        manifest: parsed,
        actor: actor.trim(),
        ...(site.trim() ? { site: site.trim() } : {}),
        ...(owner.trim() ? { owner: owner.trim() } : {}),
      },
    });
    setBusy(false);
    setOut(res);
    if (res.kind === 'ok' && res.data.written) onChanged();
  };

  const refusalReceipt = out?.kind === 'conflict' ? receiptOf(out.receipt) : null;

  return (
    <section id="aw-enrol" aria-labelledby="aw-enrol-h">
      <h2 id="aw-enrol-h">Enrol a machine</h2>
      <p className="aw-note">
        Declares that a machine is one your ledger keeps a record of, and seals its manifest as the baseline
        configuration (<code>POST /v1/machinery/enrol</code>). It is a declaration by a named person. It runs no
        verification: every safety function reads <code>never_verified</code> until one is recorded. Enrolling the same
        configuration again writes nothing; a different one is drift, not an enrolment.
      </p>
      <label className="aw-field">
        Safety manifest (JSON), pasted
        <textarea
          className="aw-textarea"
          rows={6}
          value={manifest}
          onChange={(e) => {
            setManifest(e.target.value);
            setFileName('');
          }}
        />
      </label>
      <label className="aw-field">
        Or load a manifest file{fileName ? ` (loaded: ${fileName})` : ''}
        <input type="file" accept=".json,application/json" onChange={(e) => void readFile(e.target.files?.[0])} />
      </label>
      <label className="aw-field">
        Site (optional)
        <input type="text" value={site} onChange={(e) => setSite(e.target.value)} />
      </label>
      <label className="aw-field">
        Owner (optional)
        <input type="text" value={owner} onChange={(e) => setOwner(e.target.value)} />
      </label>
      <label className="aw-field">
        Your name (required: the person making this declaration)
        <input type="text" value={actor} onChange={(e) => setActor(e.target.value)} autoComplete="name" />
      </label>
      <button className="btn btn-outline" disabled={busy} onClick={() => void run()}>
        {busy ? 'Enrolling…' : 'Enrol machine'}
      </button>

      <div ref={result} tabIndex={-1} aria-live="polite" className="aw-result" data-testid="enrol-result">
        {notice && <Notice>{notice}</Notice>}
        {out && out.kind !== 'ok' && !refusalReceipt && <Refusal outcome={out} what="Enrolment" />}
        {out?.kind === 'conflict' && refusalReceipt && (
          <>
            <div className="aw-alert" role="alert" data-outcome="conflict" data-testid="enrol-conflict">
              <strong>Refused (409), nothing was written.</strong> {out.message}
            </div>
            <EnrolReceiptView receipt={refusalReceipt} />
          </>
        )}
        {out?.kind === 'ok' && <EnrolReceiptView receipt={out.data} />}
      </div>
    </section>
  );
}
