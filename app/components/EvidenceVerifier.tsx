'use client';

import { useEffect, useRef, useState } from 'react';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';
// Mirrors ASSURANCE_MAX_EVIDENCE_BODY_BYTES' default (src/assurance/api/deps.py).
// The server enforces it; this only saves a pointless upload.
const MAX_BYTES = 4 * 1024 * 1024;

// POST /v1/evidence/verify — the uniform result (src/assurance/api/evidence_routes.py).
export type Outcome =
  | 'no_inconsistency_found'
  | 'signatures_not_checked'
  // Nothing was found wrong, but something asked for (completeness against a signed head,
  // typically) could not be established. NOT a finding that the file was changed.
  | 'not_established'
  | 'inconsistent'
  | 'unreadable'
  | 'unsupported'
  | 'check_failed';

export type VerifyResult = {
  kind: 'ledger_export' | 'machine_bundle' | 'attestation_log' | 'unknown';
  outcome: Outcome;
  // True means only: no inconsistency was found in the checks that ran. It is not "complete"
  // and not "reproduced": read `completeness` (ledger exports) and `level` (machine bundles).
  ok: boolean;
  // Attestation logs only (null otherwise): whether any signature was actually checked.
  signatures_verified: boolean | null;
  // Ledger exports only (null otherwise): did a signed anchor, under the key supplied,
  // show nothing was removed? 'anchored' = a head the signer READ from the ledger covers the
  // last record; 'anchored_partial' = records follow that head and no signature covers them;
  // 'declared_head' = the signer was only TOLD the head and never read the chain (not an
  // anchor); 'not_checked' is the default and is never a pass.
  completeness?: 'anchored' | 'anchored_partial' | 'declared_head' | 'not_checked' | 'failed' | null;
  anchor?: {
    head_seq: number;
    records_after_anchor: number;
    // read_from_ledger: the signer read the chain. declared_by_holder: it was handed three numbers.
    basis?: 'read_from_ledger' | 'declared_by_holder' | string;
  } | null;
  // Ledger exports only: what was asked for and could not be established (not tampering).
  unestablished?: string[];
  scope: string;
  entries: number;
  verified: string[];
  problems: string[];
  assumptions: string[];
  not_checked: string[];
  tier: {
    recorded_tier: string | null;
    recorded_verdict: string | null;
    as_recorded_may_claim_physical_behaviour: boolean | null;
    evidence_required: string;
    product?: string | null;
    product_version?: string | null;
    provenance?: string | null;
    // Who vouches for `provenance`: 'declared_by_filer' = the filer said so, nothing signed it.
    provenance_basis?: string | null;
    trace_started_at?: string | null;
  } | null;
  head: { seq: number; link_hash: string; length: number } | null;
  summary: string;
  stored: boolean;
};

const KIND_LABEL: Record<VerifyResult['kind'], string> = {
  ledger_export: 'Ledger export (hash-chained evidence)',
  machine_bundle: 'Machine verification bundle',
  attestation_log: 'Signed head attestation log',
  unknown: 'Not recognised',
};

// The colour says how much to rely on the answer: green only for a ledger export whose signed
// head the signer READ from the ledger and that covers its last record. Everything else that is
// not a finding of tampering is amber, because "no inconsistency found" is not "complete".
export function headlineText(r: VerifyResult): string {
  if (r.outcome === 'no_inconsistency_found' && r.completeness === 'declared_head') {
    return 'No inconsistency found — but the signed head was only declared to the signer, so completeness is not shown';
  }
  return HEADLINE[r.outcome];
}

export function headlineTone(r: VerifyResult): 'success' | 'caution' | 'danger' {
  if (r.outcome === 'inconsistent' || r.outcome === 'check_failed') return 'danger';
  if (r.outcome === 'no_inconsistency_found' && r.completeness === 'anchored') return 'success';
  return 'caution';
}

const PROVENANCE_BASIS: Record<string, string> = {
  declared_by_filer: 'declared by the filer — nothing signed the recording',
};

// Deliberately no "valid", "passed" or tick: the strongest thing any outcome says
// is that the checks that ran found nothing wrong.
const HEADLINE: Record<Outcome, string> = {
  no_inconsistency_found: 'No inconsistency found in the checks that ran',
  signatures_not_checked: 'Structure only — no signature was checked',
  not_established: 'Could not be established — nothing wrong was found, but a check you asked for could not be completed',
  inconsistent: 'Problems found',
  unreadable: 'Could not read this file — nothing was checked',
  unsupported: 'Not a file this page can check',
  check_failed: 'The check could not be completed — this is not a pass',
};

const css = `
.ev-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; align-items: start; }
@media (max-width: 860px) { .ev-grid { grid-template-columns: 1fr; } }
.ev-drop { border: 2px dashed var(--border); border-radius: var(--radius-md); background: var(--surface-alt);
  padding: 1rem; text-align: center; font-size: 0.9rem; color: var(--ink-soft); }
.ev-drop[data-over='true'] { border-color: var(--orange); background: #fff7ee; }
.ev-text { width: 100%; min-height: 220px; font: 0.78rem/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  border: 1px solid var(--border); border-radius: var(--radius-md); padding: 0.75rem; background: var(--surface); color: var(--ink); resize: vertical; }
.ev-panel { border: 1px solid var(--border); border-radius: var(--radius-md); padding: 1rem; background: var(--surface); display: flex; flex-direction: column; gap: 0.9rem; min-width: 0; }
.ev-headline { font-weight: 700; font-size: 1.05rem; margin: 0; }
.ev-headline[data-tone='success'] { color: var(--success); }
.ev-headline[data-tone='danger'] { color: var(--danger); }
.ev-headline[data-tone='caution'] { color: var(--orange-dark); }
.ev-sec h3 { font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.06em; margin: 0 0 0.35rem; color: var(--ink-soft); }
.ev-sec ul { margin: 0; padding-left: 1.1rem; display: flex; flex-direction: column; gap: 0.3rem; font-size: 0.86rem; line-height: 1.5; }
.ev-sec[data-kind='problems'] { border-left: 3px solid var(--danger); padding-left: 0.75rem; }
.ev-sec[data-kind='unestablished'] { border-left: 3px solid var(--orange); padding-left: 0.75rem; }
.ev-sec[data-kind='verified'] { border-left: 3px solid var(--success); padding-left: 0.75rem; }
.ev-sec[data-kind='assumed'] { border-left: 3px solid var(--orange); padding-left: 0.75rem; }
.ev-sec[data-kind='notchecked'] { border-left: 3px solid var(--ink-soft); padding-left: 0.75rem; }
.ev-meta { font-size: 0.8rem; color: var(--ink-soft); margin: 0; }
.ev-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.74rem; word-break: break-all; }
.ev-note { font-size: 0.82rem; color: var(--ink-soft); line-height: 1.55; margin: 0; }
.ev-err { color: var(--danger); font-size: 0.88rem; margin: 0; }
.ev-row { display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: center; }
`;

function List({ kind, title, items }: { kind: string; title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <section className="ev-sec" data-kind={kind} data-testid={`ev-${kind}`}>
      <h3>{title}</h3>
      <ul>
        {items.map((t, i) => (
          <li key={i}>{t}</li>
        ))}
      </ul>
    </section>
  );
}

export default function EvidenceVerifier() {
  const [text, setText] = useState('');
  const [fileName, setFileName] = useState('');
  const [keyPem, setKeyPem] = useState('');
  const [over, setOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<VerifyResult | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  // Lets a browser test wait for the handlers to be attached before it drops a file.
  const [ready, setReady] = useState(false);
  useEffect(() => setReady(true), []);

  // The key box opens for an attestation log, and for a ledger export that carries a
  // signed anchor (the only thing that can show nothing was removed from it).
  const looksLikeAttestation =
    (/head_link_hash/.test(text) && !/"entries"\s*:/.test(text)) || /"anchor"\s*:\s*\{/.test(text);

  async function load(file: File) {
    setResult(null);
    setError(null);
    if (file.size > MAX_BYTES) {
      setFileName('');
      setText('');
      setError(
        `That file is ${(file.size / 1024 / 1024).toFixed(1)} MiB. This page checks files up to 4 MiB; check larger exports offline with python -m assurance evidence verify.`,
      );
      return;
    }
    setFileName(file.name);
    // Read as text exactly as it is: the hashes cover the file's own numbers, so the
    // page must never parse and re-serialise it.
    setText(await file.text());
  }

  async function run() {
    setError(null);
    setResult(null);
    if (!API_BASE) {
      setError(
        'No Assurance API is configured for this site (NEXT_PUBLIC_ASSURANCE_API_URL is not set), so this page cannot check anything and will not pretend to. Run the same verifier on your own machine — see "Check it offline" below.',
      );
      return;
    }
    if (!text.trim()) {
      setError('Choose or paste a JSON file first.');
      return;
    }
    // A private key never needs to leave this browser, and nothing here wants one.
    if (/PRIVATE/i.test(keyPem) || /BEGIN [A-Z ]*PRIVATE KEY/i.test(text)) {
      setError(
        'That looks like a private key. It was not sent. Only a PUBLIC key is ever needed here — and if this was a real private key, treat it as exposed and replace it.',
      );
      return;
    }
    if (new Blob([text]).size > MAX_BYTES) {
      setError('That is larger than 4 MiB. Check it offline with python -m assurance evidence verify.');
      return;
    }
    setBusy(true);
    try {
      // The public key goes in a header, not the URL: URLs are logged. A header cannot
      // hold line breaks, so the PEM travels on one line and the server re-wraps it.
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (keyPem.trim()) headers['X-Issuer-Public-Key'] = keyPem.trim().split(/\s+/).join(' ');
      const res = await fetch(`${API_BASE}/v1/evidence/verify`, { method: 'POST', headers, body: text });
      const body = await res.json().catch(() => null);
      if (res.status === 429) {
        const d = body?.detail;
        setError(
          `Daily allowance used (${d?.used ?? '?'} of ${d?.limit ?? '?'} checks from this address today). It resets at 00:00 UTC. The offline verifier has no limit.`,
        );
      } else if (res.status === 422 && body?.detail?.error === 'private_key_refused') {
        setError(body.detail.detail);
      } else if (res.status === 503 && body?.detail?.error === 'verifier_busy') {
        setError('The checker is busy with other files. Nothing was counted against your allowance — try again in a few seconds.');
      } else if (res.status === 413) {
        setError('The service refused the file as too large. Check it offline with python -m assurance evidence verify.');
      } else if (!res.ok || !body || typeof body.outcome !== 'string') {
        setError(`The service answered ${res.status} without a result. Nothing was checked.`);
      } else {
        setResult(body as VerifyResult);
      }
    } catch {
      setError('Could not reach the API host. It may not be deployed, or your network blocked the request. Nothing was checked.');
    }
    setBusy(false);
  }

  return (
    <div className="ev" data-testid="evidence-verifier" data-ready={ready}>
      <style>{css}</style>
      <div className="ev-grid">
        <div className="ev-panel">
          <div
            className="ev-drop"
            data-over={over}
            data-testid="ev-drop"
            onDragOver={(e) => {
              e.preventDefault();
              setOver(true);
            }}
            onDragLeave={() => setOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setOver(false);
              const f = e.dataTransfer.files?.[0];
              if (f) void load(f);
            }}
          >
            <p style={{ margin: '0 0 0.5rem' }}>Drop a JSON evidence file here, or</p>
            <input
              ref={inputRef}
              type="file"
              accept=".json,.jsonl,application/json,text/plain"
              aria-label="Evidence file"
              data-testid="ev-file"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void load(f);
              }}
            />
            {fileName && (
              <p className="ev-meta" style={{ marginTop: '0.5rem' }} data-testid="ev-filename">
                {fileName} · {text.length.toLocaleString()} characters
              </p>
            )}
          </div>

          <label htmlFor="ev-text" className="ev-meta">
            …or paste the file&apos;s text exactly as it is (do not reformat it)
          </label>
          <textarea
            id="ev-text"
            className="ev-text"
            data-testid="ev-text"
            spellCheck={false}
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setFileName('');
            }}
            placeholder='{"ledger_schema_version": 1, "chain_verified": true, "entries": [ … ]}'
          />

          <details open={looksLikeAttestation}>
            <summary className="ev-meta" style={{ cursor: 'pointer' }}>
              Signed files: the issuer&apos;s public key (attestation logs, and whether a ledger export is complete)
            </summary>
            <p className="ev-note" style={{ margin: '0.5rem 0' }}>
              A signature can only be checked against a public key you got <em>somewhere other than the file</em> —
              a file carries a key fingerprint, not the key. Without one, an attestation log&apos;s structure is
              checked, its signatures are reported as <strong>not verified</strong>, and the result is{' '}
              <strong>never shown as a pass</strong>. A ledger export is the same: without the key of the signed head
              it carries, <strong>completeness is reported as not checked</strong> (entries cut from the end, or a
              rebuilt chain, would look identical). With the key, a <em>one-case</em> export can only be shown complete
              if the exporter included the ledger skeleton (<code>?skeleton=true</code>); without it the answer is
              &ldquo;could not be established&rdquo;, which is not a finding of tampering. A head the signer was only
              told (<code>declared_by_holder</code>) is never an anchor. Paste a public key only: a private key is
              refused and never sent.
            </p>
            <textarea
              className="ev-text"
              style={{ minHeight: '90px' }}
              aria-label="Issuer public key (PEM)"
              data-testid="ev-key"
              spellCheck={false}
              value={keyPem}
              onChange={(e) => setKeyPem(e.target.value)}
              placeholder={'-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----'}
            />
          </details>

          <div className="ev-row">
            <button className="btn btn-primary" onClick={() => void run()} disabled={busy} data-testid="ev-run">
              {busy ? 'Checking…' : 'Check this file'}
            </button>
            {!API_BASE && (
              <span className="ev-err" data-testid="ev-no-api">
                No API is configured for this site, so this button cannot check anything.
              </span>
            )}
          </div>
          <p className="ev-note" data-testid="ev-stateless">
            Nothing is stored. The file is sent to the Assurance API, checked in memory and dropped; the only
            record is the ordinary access-log line (time, path, status — never the file; a public key you paste, for an
            attestation check or to check a ledger export against its signed head, travels in a request header, which the
            access log does not record). It counts as one of your free daily checks from this address.
          </p>
          {error && (
            <p className="ev-err" role="alert" data-testid="ev-error">
              {error}
            </p>
          )}
        </div>

        <div className="ev-panel" aria-live="polite" data-testid="ev-result">
          {!result && !error && (
            <p className="ev-note">
              The result lists three things separately, and never as a single tick: the{' '}
              <strong>facts a check established</strong>, the <strong>assumptions</strong> a pass still takes on
              trust, and every <strong>check not performed</strong>.
            </p>
          )}
          {result && (
            <>
              <h2
                className="ev-headline"
                data-outcome={result.outcome}
                data-tone={headlineTone(result)}
                data-testid="ev-headline"
              >
                {headlineText(result)}
              </h2>
              <p className="ev-meta" data-testid="ev-kind">
                Detected: <strong>{KIND_LABEL[result.kind]}</strong>
                {result.scope ? ` · ${result.scope}` : ''}
                {result.signatures_verified === false ? ' · signatures NOT verified' : ''}
                {result.signatures_verified === true ? ' · signatures verified against the key you supplied' : ''}
                {result.completeness === 'anchored'
                  ? ' · matches a signed head that the signer read from the ledger (basis read_from_ledger) and that covers its last record (key you supplied)'
                  : ''}
                {result.completeness === 'anchored_partial'
                  ? ` · matches a signed head the signer read from the ledger, but only up to seq ${result.anchor?.head_seq ?? '?'}; ${result.anchor?.records_after_anchor ?? 'some'} later record(s) are covered by no signature`
                  : ''}
                {result.completeness === 'declared_head'
                  ? ` · matches a head that was only DECLARED to the signer (basis ${result.anchor?.basis ?? 'declared_by_holder'}): the signer never read the chain, so this is not an anchor`
                  : ''}
                {result.completeness === 'not_checked' ? ' · completeness NOT checked' : ''}
                {result.completeness === 'failed' ? ' · does not match its signed head' : ''}
                {result.kind !== 'unknown' && result.entries > 0 ? ` · ${result.entries} record(s)` : ''}
              </p>
              <p className="ev-note" data-testid="ev-summary">
                {result.summary}
              </p>
              <List kind="problems" title="Problems found" items={result.problems} />
              <List
                kind="unestablished"
                title="Could not be established (not a finding that the file was changed)"
                items={result.unestablished ?? []}
              />
              <List kind="verified" title="Facts a check established" items={result.verified} />
              {result.tier && (
                <section className="ev-sec" data-testid="ev-tier">
                  <h3>What the file records (not established by this check)</h3>
                  <ul>
                    <li>
                      Verdict: <strong>{result.tier.recorded_verdict ?? 'unknown'}</strong> · assurance tier:{' '}
                      <strong>{result.tier.recorded_tier ?? 'unknown'}</strong>
                      {result.tier.provenance
                        ? ` · run provenance: ${result.tier.provenance}${
                            result.tier.provenance_basis
                              ? ` (${PROVENANCE_BASIS[result.tier.provenance_basis] ?? result.tier.provenance_basis})`
                              : ''
                          }`
                        : ''}
                    </li>
                    {result.tier.as_recorded_may_claim_physical_behaviour !== null && (
                      <li>
                        The file says this tier would allow a claim about the physical machine:{' '}
                        <strong>{result.tier.as_recorded_may_claim_physical_behaviour ? 'yes' : 'no'}</strong>{' '}
                        (as recorded in the file — a seal is not a signature, and this check did not establish it)
                      </li>
                    )}
                    {result.tier.evidence_required && <li>This tier requires: {result.tier.evidence_required}</li>}
                  </ul>
                </section>
              )}
              {result.head && (
                <section className="ev-sec" data-testid="ev-head">
                  <h3>Head to compare with a signed attestation</h3>
                  <p className="ev-meta">
                    seq {result.head.seq} of {result.head.length} · link hash{' '}
                    <span className="ev-mono">{result.head.link_hash}</span>
                  </p>
                </section>
              )}
              <List kind="assumed" title="Assumptions — taken on trust, not checked" items={result.assumptions} />
              <List kind="notchecked" title="Checks not performed" items={result.not_checked} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
