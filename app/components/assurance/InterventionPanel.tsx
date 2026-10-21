'use client';

import { useState } from 'react';
import { call, type ApiOutcome, type AssessInterventionResult } from '../../lib/assuranceApi';
import { Notice, Refusal } from './PanelFrame';
import { openedOrExisting, queueIds } from './caseIds';
import { API_BASE } from './usePanel';

// POST /v1/change/assess/intervention. The intervention must already be sealed in the
// account's ledger (POST /v1/machinery/intervention); the server looks it up there and takes
// the verifications from the ledger, never from this form.
export default function InterventionPanel({
  apiKey,
  actor,
  setActor,
  onOpenCase,
  onChanged,
}: {
  apiKey: string;
  actor: string;
  setActor: (v: string) => void;
  onOpenCase: (id: string) => void;
  onChanged: () => void;
}) {
  const [manifest, setManifest] = useState('');
  const [id, setId] = useState('');
  const [busy, setBusy] = useState(false);
  const [existing, setExisting] = useState<Set<string> | null>(null);
  const [notice, setNotice] = useState('');
  const [out, setOut] = useState<ApiOutcome<AssessInterventionResult> | null>(null);

  const run = async () => {
    setNotice('');
    setOut(null);
    if (!API_BASE || !apiKey) {
      setNotice('Paste an API key first.');
      return;
    }
    if (!id.trim()) {
      setNotice('Enter the id of the intervention you sealed.');
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(manifest);
    } catch {
      setNotice('That manifest is not valid JSON.');
      return;
    }
    setBusy(true);
    const before = await queueIds(apiKey);
    setExisting(before);
    const res = await call<AssessInterventionResult>(API_BASE, apiKey, '/v1/change/assess/intervention', {
      method: 'POST',
      body: { manifest: parsed, intervention_id: id.trim(), ...(actor.trim() ? { actor: actor.trim() } : {}) },
    });
    setBusy(false);
    setOut(res);
    if (res.kind === 'ok' && res.data.opened) onChanged();
  };

  return (
    <section id="aw-intervention" aria-labelledby="aw-intervention-h">
      <h2 id="aw-intervention-h">Assess a recorded intervention</h2>
      <p className="aw-note">
        Asks whether a change to a machine&apos;s safety software that you already sealed (
        <code>POST /v1/machinery/intervention</code>) put standing evidence in question. The server reads the
        intervention and the machine&apos;s verifications from your ledger. A case opens only if it did.
      </p>
      <label className="aw-field">
        Safety manifest (JSON) of the machine
        <textarea className="aw-textarea" rows={4} value={manifest} onChange={(e) => setManifest(e.target.value)} />
      </label>
      <label className="aw-field">
        Intervention id
        <input type="text" value={id} onChange={(e) => setId(e.target.value)} />
      </label>
      <label className="aw-field">
        Your name (optional here; recorded when given)
        <input type="text" value={actor} onChange={(e) => setActor(e.target.value)} />
      </label>
      <button className="btn btn-outline" disabled={busy} onClick={() => void run()}>
        {busy ? 'Assessing…' : 'Assess intervention'}
      </button>
      {notice && <Notice>{notice}</Notice>}
      {out && out.kind !== 'ok' && <Refusal outcome={out} what="Intervention" />}
      {out?.kind === 'ok' && (
        <div className="aw-prov" role="status" data-testid="intervention-result">
          {out.data.opened && out.data.case ? (
            <p>
              Intervention {out.data.intervention_id} put standing evidence in question.{' '}
              {openedOrExisting(existing, out.data.case.case_id, out.data.case.status)}{' '}
              <button className="aw-link" onClick={() => onOpenCase(out.data.case!.case_id)}>
                Open case {out.data.case.case_id}
              </button>
            </p>
          ) : (
            <p>
              No case opened for {out.data.intervention_id}: it did not invalidate any function that had standing
              evidence. That does not say the change was authorised or re-validated.
            </p>
          )}
        </div>
      )}
    </section>
  );
}
