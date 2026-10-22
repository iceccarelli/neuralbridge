'use client';

import { useEffect, useState } from 'react';
import { call, explainForbidden, type ApiOutcome, type KeyPin, type SupplierTrust } from '../../lib/assuranceApi';
import DecisionCredential, { useOperatorKey } from './DecisionCredential';
import { Notice, PanelFrame, Refusal } from './PanelFrame';
import { API_BASE, usePanel } from './usePanel';

type Field = {
  name: string;
  label: string;
  area?: boolean;
  required?: boolean;
  placeholder?: string;
};

const PIN_FIELDS: Field[] = [
  {
    name: 'supplier_id',
    label: 'Supplier id (as it appears in the feed)',
    required: true,
  },
  {
    name: 'public_key_pem',
    label: 'Supplier public key (PEM)',
    area: true,
    required: true,
  },
  {
    name: 'expected_fingerprint',
    label: 'Fingerprint you were told (the key must match it)',
    placeholder: 'recommended',
  },
  {
    name: 'obtained_via',
    label: 'How you obtained this key or fingerprint, independently of the feed',
    required: true,
    placeholder: 'e.g. signed contract annex 4, or a call to the supplier’s published number',
  },
  { name: 'reason', label: 'Reason' },
];

const ROTATE_FIELDS: Field[] = [
  { name: 'supplier_id', label: 'Supplier id', required: true },
  {
    name: 'new_public_key_pem',
    label: 'New public key (PEM)',
    area: true,
    required: true,
  },
  {
    name: 'retire_fingerprint',
    label: 'Fingerprint of the key to retire',
    required: true,
  },
  {
    name: 'effective_at',
    label: 'Effective at (UTC timestamp, e.g. 2026-11-01T00:00:00Z)',
    required: true,
  },
  {
    name: 'expected_fingerprint',
    label: 'Fingerprint of the new key you were told',
  },
  {
    name: 'obtained_via',
    label: 'How you obtained the new key, independently of the feed',
    required: true,
  },
  { name: 'reason', label: 'Reason' },
];

const REVOKE_FIELDS: Field[] = [
  { name: 'supplier_id', label: 'Supplier id', required: true },
  { name: 'fingerprint', label: 'Fingerprint to revoke', required: true },
  { name: 'reason', label: 'Why (required)', required: true },
];

function TrustForm({
  kind,
  title,
  fields,
  apiKey,
  opKey,
  warning,
  submit,
  onDone,
}: {
  kind: 'pin' | 'rotate' | 'revoke';
  title: string;
  fields: Field[];
  apiKey: string;
  opKey: string;
  warning: string;
  submit: string;
  onDone: () => void;
}) {
  const [vals, setVals] = useState<Record<string, string>>({});
  const [out, setOut] = useState<ApiOutcome<{ pin: KeyPin }> | null>(null);
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);

  const send = async () => {
    setNotice('');
    setOut(null);
    const missing = fields.filter((f) => f.required && !(vals[f.name] || '').trim());
    if (missing.length) {
      setNotice(`Needed before anything is sent: ${missing.map((m) => m.label).join('; ')}.`);
      return;
    }
    const body: Record<string, string> = {};
    for (const f of fields) body[f.name] = (vals[f.name] || '').trim();
    setBusy(true);
    // A trust decision is a human decision: it goes with the decider operator's key, and the server
    // records that operator as the actor. No name is typed or sent.
    const res = await call<{ pin: KeyPin }>(API_BASE, opKey.trim(), `/v1/supplier/trust/${kind}`, {
      method: 'POST',
      body,
    });
    setBusy(false);
    setOut(res);
    if (res.kind === 'ok') {
      setVals({});
      onDone();
    }
  };

  return (
    <details data-testid={`trust-form-${kind}`}>
      <summary>{title}</summary>
      <p className="aw-note">{warning}</p>
      {fields.map((f) => (
        <label className="aw-field" key={f.name}>
          {f.label}
          {f.area ? (
            <textarea
              className="aw-textarea"
              rows={4}
              value={vals[f.name] || ''}
              onChange={(e) => setVals({ ...vals, [f.name]: e.target.value })}
              name={`${kind}-${f.name}`}
            />
          ) : (
            <input
              type="text"
              value={vals[f.name] || ''}
              placeholder={f.placeholder}
              onChange={(e) => setVals({ ...vals, [f.name]: e.target.value })}
              name={`${kind}-${f.name}`}
            />
          )}
        </label>
      ))}
      <button className="btn btn-outline" disabled={busy || !opKey.trim()} onClick={() => void send()}>
        {submit}
      </button>
      {!opKey.trim() && (
        <p className="aw-note" data-testid={`trust-${kind}-disabled-why`}>
          Disabled: this is a human decision and needs a decision credential (the key of a decider operator). Enter it
          under Decision credential above.
        </p>
      )}
      {notice && <Notice>{notice}</Notice>}
      {out && out.kind !== 'ok' && <Refusal outcome={out} what={title} />}
      {out && out.kind === 'forbidden' && explainForbidden(out) && <p className="aw-note">{explainForbidden(out)}</p>}
      {out?.kind === 'ok' && (
        <p className="aw-prov" role="status" data-testid={`trust-${kind}-done`}>
          Recorded: key <code>{out.data.pin.fingerprint}</code> for {out.data.pin.supplier_id} is now{' '}
          <strong>{out.data.pin.status}</strong>, by {out.data.pin.pinned_by}. This records what a person said; it does
          not check that they were right.
        </p>
      )}
    </details>
  );
}

function pinState(p: KeyPin): string {
  if (p.status === 'revoked') return `revoked${p.revoked_at ? ` ${p.revoked_at}` : ''}`;
  if (p.retired_at) return `retires/retired ${p.retired_at}`;
  return p.status;
}

// The keys this account trusts for supplier feeds, in the account's own ledger. A pin says "a
// person told us this fingerprint belongs to this supplier" and records how. It does not make
// any advisory correct.
export default function SupplierKeys({
  apiKey,
  onChanged,
  version = 0,
}: {
  apiKey: string;
  onChanged?: () => void;
  /** Bumped by the page when a trust decision is made elsewhere (an override), so the list re-reads. */
  version?: number;
}) {
  const trust = usePanel<SupplierTrust>(apiKey, '/v1/supplier/trust');
  const [opKey, setOpKey] = useOperatorKey();
  const reloadTrust = trust.reload;
  useEffect(() => {
    if (version > 0) void reloadTrust();
  }, [version, reloadTrust]);
  const done = () => {
    void trust.reload();
    onChanged?.();
  };
  return (
    <PanelFrame
      id="aw-supplier-keys"
      title="Supplier keys"
      what="the supplier keys"
      apiKey={apiKey}
      panel={trust}
      notFoundNote=""
    >
      {(t) => (
        <div data-testid="supplier-keys">
          <DecisionCredential apiKey={apiKey} opKey={opKey} setOpKey={setOpKey} />
          <p className="aw-prov" data-testid="key-not-proof">
            <strong>A key inside an advisory, or beside a feed, is not proof.</strong> A forged feed carries its own
            key. Pin a key only with a fingerprint you obtained by another route (a contract, a call to a number you
            already had) and record how. Pins are kept in your account&apos;s own ledger and decide which feeds may
            drive consequences; they never decide whether an advisory is right.
          </p>
          {t.integrity_problems.length > 0 && (
            <div className="aw-alert" role="alert" data-testid="trust-integrity">
              <strong>THE TRUST STORE DOES NOT CHECK OUT — no feed is trusted until this is explained.</strong>
              <ul>
                {t.integrity_problems.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            </div>
          )}
          {t.pins.length === 0 ? (
            <p className="console-empty-note" data-testid="no-pins">
              No supplier key is pinned for this account. Every feed will read as <strong>not trusted</strong> (unknown
              key): it can be inspected, and nothing automated may follow from it.
            </p>
          ) : (
            <div className="aw-scroll">
              <table className="aw-table" data-testid="pins-table">
                <thead>
                  <tr>
                    <th>Supplier</th>
                    <th>Fingerprint</th>
                    <th>State</th>
                    <th>In force from</th>
                    <th>Pinned by</th>
                    <th>Obtained via</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {t.pins.map((p) => (
                    <tr
                      key={`${p.supplier_id}-${p.fingerprint}`}
                      data-testid="pin-row"
                      data-fingerprint={p.fingerprint}
                      data-status={p.status}
                    >
                      <td>{p.supplier_id}</td>
                      <td>
                        <code>{p.fingerprint}</code>
                      </td>
                      <td className={p.status === 'revoked' ? 'aw-bad' : undefined}>{pinState(p)}</td>
                      <td>{p.effective_from}</td>
                      <td>
                        {p.pinned_by}
                        <br />
                        <span className="aw-note">{p.pinned_at}</span>
                      </td>
                      <td>{p.obtained_via || 'not recorded'}</td>
                      <td>{p.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {t.overrides.length > 0 && (
            <>
              <h4>Manual overrides on record</h4>
              <ul data-testid="overrides-list">
                {t.overrides.map((o) => (
                  <li key={`${o.advisory_id}-${o.at}`}>
                    {o.advisory_id} from {o.supplier_id}: accepted by <strong>{o.actor}</strong> at {o.at} — {o.reason}{' '}
                    (bound to content hash <code>{o.advisory_hash.slice(0, 12)}</code>; it does not pin the key)
                  </li>
                ))}
              </ul>
            </>
          )}
          <TrustForm
            kind="pin"
            title="Pin a supplier key"
            fields={PIN_FIELDS}
            apiKey={apiKey}
            opKey={opKey}
            submit="Pin key"
            warning="A pin records that you were told this key belongs to this supplier, and how. It does not check that you were told the truth. Do not copy a key or fingerprint out of the feed you are trying to judge."
            onDone={done}
          />
          <TrustForm
            kind="rotate"
            title="Rotate a supplier key"
            fields={ROTATE_FIELDS}
            apiKey={apiKey}
            opKey={opKey}
            submit="Pin new key and retire the old"
            warning="Pins the new key and retires the old one from the effective date. Records signed by the old key before that date stay in force; records after it are not trusted under it."
            onDone={done}
          />
          <TrustForm
            kind="revoke"
            title="Revoke a supplier key"
            fields={REVOKE_FIELDS}
            apiKey={apiKey}
            opKey={opKey}
            submit="Revoke key"
            warning="Everything signed by this key stops being trusted, including advisories already assessed. Use it when a key may be compromised."
            onDone={done}
          />
          <p className="aw-note" data-testid="trust-statement-keys">
            {t.trust_statement}
          </p>
        </div>
      )}
    </PanelFrame>
  );
}
