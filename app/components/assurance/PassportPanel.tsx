'use client';

import { useEffect, useRef, useState } from 'react';
import { actorProblem, type ApiOutcome } from '../../lib/assuranceApi';
import { assemblePassport, checkPassport, readPassport, type PassportCheck, type PassportDoc } from '../../lib/passportApi';
import PassportView from './PassportView';
import { Notice, Refusal } from './PanelFrame';
import { API_BASE } from './usePanel';

type Shown = { doc: PassportDoc; source: string; check: ApiOutcome<PassportCheck> | null };

// A machine passport: what it asserts, the evidence it rests on, whether its seal and internal
// consistency hold, who is named as sealing it, and what is left unchecked. Two ways in, one
// view. (1) A passport file produced by `assurance machinery passport` or the API, pasted or
// loaded here and re-checked by POST /v1/machinery/passport/check, which is free and needs no
// key. (2) A current passport assembled from a manifest by POST /v1/machinery/passport with
// seal:false, which writes nothing to the ledger. This panel seals nothing and decides nothing.
export default function PassportPanel({ apiKey, actor, setActor }: { apiKey: string; actor: string; setActor: (v: string) => void }) {
  const [text, setText] = useState('');
  const [fileName, setFileName] = useState('');
  const [manifest, setManifest] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [refused, setRefused] = useState<ApiOutcome<unknown> | null>(null);
  const [shown, setShown] = useState<Shown | null>(null);
  const result = useRef<HTMLDivElement>(null);
  const seq = useRef(0);

  useEffect(() => {
    if (shown || notice || refused) result.current?.focus();
  }, [shown, notice, refused]);

  const reset = () => {
    seq.current++;
    setNotice('');
    setRefused(null);
    setShown(null);
  };

  const parse = (raw: string, what: string): unknown | undefined => {
    try {
      return JSON.parse(raw);
    } catch {
      setNotice(`That ${what} could not be read as JSON.`);
      return undefined;
    }
  };

  // Show the document at once, then the check when it answers; a late answer for an older
  // request is ignored.
  const show = async (raw: unknown, source: string) => {
    const read = readPassport(raw);
    if (!read.ok) {
      setNotice(read.reason);
      return;
    }
    const id = ++seq.current;
    setShown({ doc: read.doc, source, check: null });
    setBusy(true);
    const check = await checkPassport(API_BASE, raw);
    if (id !== seq.current) return;
    setBusy(false);
    setShown({ doc: read.doc, source, check });
  };

  const checkFile = async () => {
    reset();
    if (!API_BASE) {
      setNotice('The API is not configured for this site, so a passport cannot be checked here.');
      return;
    }
    if (!text.trim()) {
      setNotice('Paste a passport file or load one first.');
      return;
    }
    const raw = parse(text, 'passport');
    if (raw === undefined) return;
    await show(raw, fileName ? `the file ${fileName}` : 'the pasted text');
  };

  const assemble = async () => {
    reset();
    if (!API_BASE || !apiKey) {
      setNotice('Paste an API key first: assembling a passport reads your ledger.');
      return;
    }
    const problem = actorProblem(actor);
    if (problem) {
      setNotice(problem);
      return;
    }
    const parsed = parse(manifest, 'manifest');
    if (parsed === undefined) return;
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      setNotice('A manifest is one JSON object describing one machine.');
      return;
    }
    const id = seq.current;
    setBusy(true);
    const built = await assemblePassport(API_BASE, apiKey, parsed, actor.trim(), '');
    if (id !== seq.current) return;
    if (built.kind !== 'ok') {
      setBusy(false);
      setRefused(built);
      return;
    }
    // The assemble route adds two keys beside the passport; the file the offline command writes
    // does not have them, and the check reads the file's shape.
    const file: Record<string, unknown> = { ...built.data };
    delete file.sealed;
    delete file.verdict;
    await show(file, 'your ledger, assembled just now (not sealed, nothing written)');
  };

  const readFile = async (file: File | undefined) => {
    if (!file) return;
    setFileName(file.name);
    setText(await file.text());
  };

  return (
    <section id="aw-passport" aria-labelledby="aw-passport-h">
      <h2 id="aw-passport-h">Machine passport</h2>
      <p className="aw-note">
        A passport states one machine&apos;s evidence position: which safety functions read current, on what evidence, and what
        was not looked at. Load a passport file to re-check its seal (<code>POST /v1/machinery/passport/check</code>, free, no
        key needed), or assemble the current one from a manifest (<code>POST /v1/machinery/passport</code> with{' '}
        <code>seal: false</code>: nothing is written to your ledger). The check does not look up the records a passport
        names; that needs the offline command with the ledger.
      </p>

      <label className="aw-field">
        Passport file (JSON), pasted
        <textarea
          className="aw-textarea"
          rows={6}
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setFileName('');
          }}
        />
      </label>
      <label className="aw-field">
        Or load a passport file{fileName ? ` (loaded: ${fileName})` : ''}
        <input type="file" accept=".json,application/json" onChange={(e) => void readFile(e.target.files?.[0])} />
      </label>
      <button className="btn btn-outline" disabled={busy} onClick={() => void checkFile()}>
        {busy ? 'Working…' : 'Check passport'}
      </button>

      <details className="aw-more">
        <summary>Assemble the current passport from a manifest</summary>
        <label className="aw-field">
          Safety manifest (JSON), pasted
          <textarea className="aw-textarea" rows={5} value={manifest} onChange={(e) => setManifest(e.target.value)} />
        </label>
        <label className="aw-field">
          Your name (required: the person named on the passport)
          <input type="text" value={actor} onChange={(e) => setActor(e.target.value)} autoComplete="name" />
        </label>
        <button className="btn btn-outline" disabled={busy} onClick={() => void assemble()}>
          {busy ? 'Working…' : 'Assemble, do not seal'}
        </button>
      </details>

      <div ref={result} tabIndex={-1} aria-live="polite" className="aw-result" data-testid="passport-result">
        {notice && <Notice>{notice}</Notice>}
        {refused && <Refusal outcome={refused} what="Passport" />}
        {shown && <PassportView doc={shown.doc} check={shown.check} source={shown.source} />}
      </div>
    </section>
  );
}
