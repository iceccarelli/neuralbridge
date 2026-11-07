'use client';

import { useEffect, useRef, useState } from 'react';
import { call, describeOutcome, parseCveId, type ApiOutcome, type IntelCve } from '../../lib/assuranceApi';
import IntelReportView from './IntelReportView';
import { Notice, Refusal } from './PanelFrame';
import { API_BASE } from './usePanel';

// GET /v1/intel/cve/{cve_id}: what the operator's recorded public sources (KEV, EPSS, NVD,
// vendor advisories) say about one CVE id. Read-only; it does not say whether any machine of
// yours is affected.
function StoreBanner({ outcome }: { outcome: Extract<ApiOutcome<unknown>, { kind: 'error' }> }) {
  const d = describeOutcome(outcome);
  return (
    <div className="aw-alert aw-store-banner" role="alert" data-outcome="intel-store" data-code={outcome.code} data-testid="intel-store-banner">
      <strong>{d.heading}.</strong> {d.text}
      <span className="aw-remedy">{d.remedy}</span>
      <span className="aw-remedy">This is not an empty result and not “no vulnerabilities”: nothing was looked up.</span>
    </div>
  );
}

export default function IntelPanel({ apiKey }: { apiKey: string }) {
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [out, setOut] = useState<ApiOutcome<IntelCve> | null>(null);
  const result = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (out || notice) result.current?.focus();
  }, [out, notice]);

  const run = async () => {
    setNotice('');
    setOut(null);
    if (!API_BASE || !apiKey) {
      setNotice('Paste an API key first.');
      return;
    }
    const { id, problem } = parseCveId(input);
    if (problem) {
      setNotice(problem);
      return;
    }
    setInput(id);
    setBusy(true);
    const res = await call<IntelCve>(API_BASE, apiKey, `/v1/intel/cve/${id}`);
    setBusy(false);
    setOut(res);
  };

  const storeDown =
    out?.kind === 'error' && out.status === 503 && (out.code === 'no_intel_store_configured' || out.code === 'intel_store_unreadable');

  return (
    <section id="aw-intel" aria-labelledby="aw-intel-h">
      <h2 id="aw-intel-h">Public intelligence lookup</h2>
      <p className="aw-note">
        Asks the operator&apos;s recorded public sources about one CVE id (<code>{'GET /v1/intel/cve/{cve_id}'}</code>). Nothing is fetched from the network and nothing is matched against your machines. Not appearing in a source
        is not the same as being absent from the world.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void run();
        }}
      >
        <label className="aw-field">
          CVE id
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="CVE-2021-44228"
            spellCheck={false}
            autoCapitalize="characters"
          />
        </label>
        <button type="submit" className="btn btn-secondary" disabled={busy}>
          {busy ? 'Looking up…' : 'Look up'}
        </button>
      </form>

      <div ref={result} tabIndex={-1} aria-live="polite" className="aw-result" data-testid="intel-result">
        {busy && (
          <p className="aw-note" role="status">
            Looking up…
          </p>
        )}
        {notice && <Notice>{notice}</Notice>}
        {out && storeDown && out.kind === 'error' && <StoreBanner outcome={out} />}
        {out && out.kind !== 'ok' && !storeDown && <Refusal outcome={out} what="Intelligence lookup" />}
        {out?.kind === 'ok' && <IntelReportView report={out.data} />}
      </div>
    </section>
  );
}
