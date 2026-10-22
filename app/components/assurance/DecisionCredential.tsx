'use client';

import { useEffect, useState } from 'react';
import { call, type ApiOutcome, type CreatedOperator, type OperatorList } from '../../lib/assuranceApi';
import { Refusal, Skeleton } from './PanelFrame';
import { API_BASE, usePanel } from './usePanel';

// The operator key lives in React state and, for the life of this tab only, in sessionStorage so
// that opening another case does not ask for it again. It is never logged, never placed in a URL,
// and never sent anywhere but the configured API as the X-API-Key of a request.
const STORAGE = 'nb-assurance-decision-credential';

export function useOperatorKey(): [string, (v: string) => void] {
  const [key, setKeyState] = useState('');
  useEffect(() => {
    try {
      const v = window.sessionStorage.getItem(STORAGE);
      if (v) setKeyState(v);
    } catch {
      /* storage blocked: the key then lives in memory only */
    }
  }, []);
  const setKey = (v: string) => {
    setKeyState(v);
    try {
      if (v) window.sessionStorage.setItem(STORAGE, v);
      else window.sessionStorage.removeItem(STORAGE);
    } catch {
      /* ignore */
    }
  };
  return [key, setKey];
}

// "Decision credential": the key of an individual operator with the decider role. The four human
// routes (decision, resume, resolve-decision, waive-reverification) need it; the server refuses
// anything else. The control only holds the key and, where the account has no operator, helps
// create the first one with the account key. It decides nothing about who may do what.
export default function DecisionCredential({
  apiKey,
  opKey,
  setOpKey,
}: {
  apiKey: string;
  opKey: string;
  setOpKey: (v: string) => void;
}) {
  // Listing works with the account key, or with any operator's key (it shows "you").
  const ops = usePanel<OperatorList>(apiKey, '/v1/operators');
  const [name, setName] = useState('');
  const [role, setRole] = useState<'decider' | 'contributor'>('decider');
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<CreatedOperator | null>(null);
  const [createOut, setCreateOut] = useState<ApiOutcome<CreatedOperator> | null>(null);
  const [notice, setNotice] = useState('');

  const list = ops.outcome?.kind === 'ok' ? ops.outcome.data : (ops.good?.data ?? null);
  const live = list ? list.operators.filter((o) => !o.disabled) : [];
  const noOperators = list !== null && live.length === 0;
  const hasDecider = live.some((o) => o.role === 'decider');

  const create = async () => {
    setNotice('');
    setCreateOut(null);
    if (!name.trim()) {
      setNotice('An operator needs a name: the person this credential is issued to.');
      return;
    }
    setBusy(true);
    // Once the account has an operator, creating another needs a decider operator's key.
    const useKey = live.length > 0 && opKey ? opKey : apiKey;
    const out = await call<CreatedOperator>(API_BASE, useKey, '/v1/operators', {
      method: 'POST',
      body: { name: name.trim(), role: noOperators ? 'decider' : role },
    });
    setBusy(false);
    setCreateOut(out);
    if (out.kind === 'ok') {
      setCreated(out.data);
      setName('');
      void ops.reload();
    }
  };

  return (
    <div className="aw-cred" data-testid="decision-credential">
      <h4>Decision credential</h4>
      <p className="aw-note">
        Closing, rejecting, deferring, resuming, answering a human question and waiving re-verification are human
        decisions. The server accepts them only with a key issued to an individual operator with the{' '}
        <strong>decider</strong> role, and attributes the action to that operator itself, not to a name you type.{' '}
        <strong>
          An operator key attributes the action to a named operator account credential; it is not identity proof.
        </strong>{' '}
        Whoever holds the key acts as that operator.
      </p>
      <label className="aw-field">
        Operator key (decider)
        <input
          type="password"
          autoComplete="off"
          value={opKey}
          onChange={(e) => setOpKey(e.target.value)}
          placeholder="Operator key"
          data-testid="decision-credential-input"
        />
      </label>
      <p className="aw-note">
        Held in this tab only (cleared when it closes), sent only to the configured API as the key of the request, never
        put in an address or logged.{' '}
        {opKey ? (
          <button type="button" className="aw-link" onClick={() => setOpKey('')}>
            Forget this key
          </button>
        ) : (
          'No decision credential entered: the four decision steps below will not be sent.'
        )}
      </p>

      {apiKey && ops.loading && !list && <Skeleton what="the operators" />}
      {ops.outcome && ops.outcome.kind !== 'ok' && <Refusal outcome={ops.outcome} what="Operators" />}
      {list && (
        <div data-testid="operators-list" data-count={live.length}>
          {live.length > 0 ? (
            <p className="aw-note">
              Operators of this account:{' '}
              {live.map((o, i) => (
                <span key={o.id}>
                  {i > 0 ? '; ' : ''}
                  <strong>{o.name}</strong> ({o.role})
                </span>
              ))}
              .{' '}
              {list.you.operator_id
                ? `You are using operator ${list.you.operator_id}.`
                : 'The key above the page is an account-level key.'}
              {!hasDecider && ' None of them is a decider, so nobody can yet make a decision.'}
            </p>
          ) : (
            <p className="aw-note" data-testid="no-operators">
              <strong>This account has no operators</strong>, so nobody can close, reject, defer, resume, answer a human
              question or waive on a case. Create the first one below; it must be a decider. Create it before handing
              any key to an agent: an account key alone cannot make these decisions.
            </p>
          )}
        </div>
      )}

      {list && (
        <details open={noOperators}>
          <summary>{noOperators ? 'Create the first operator' : 'Create another operator'}</summary>
          {!noOperators && (
            <p className="aw-note">
              With an operator already in place, creating another needs a decider operator&apos;s key (enter it above).
            </p>
          )}
          <label className="aw-field">
            Operator name (the person this credential is issued to)
            <input type="text" value={name} onChange={(e) => setName(e.target.value)} data-testid="operator-name" />
          </label>
          {!noOperators && (
            <label className="aw-field">
              Role
              <select value={role} onChange={(e) => setRole(e.target.value as 'decider' | 'contributor')}>
                <option value="decider">decider — may make human decisions</option>
                <option value="contributor">contributor — may not</option>
              </select>
            </label>
          )}
          <button className="btn btn-outline" disabled={busy} onClick={() => void create()}>
            {noOperators ? 'Create first operator (decider)' : 'Create operator'}
          </button>
          {notice && (
            <div className="aw-alert" role="alert" data-outcome="local">
              {notice}
            </div>
          )}
          {createOut && createOut.kind !== 'ok' && <Refusal outcome={createOut} what="Create operator" />}
        </details>
      )}

      {created && (
        <div className="aw-alert" role="alert" data-testid="operator-key-once" data-outcome="local">
          <p>
            <strong>
              Operator {created.name} ({created.role}) created. This key is shown once and cannot be retrieved again.
            </strong>{' '}
            Copy it to a secret store now. Anyone who holds it can act as {created.name}.
          </p>
          <input
            type="text"
            readOnly
            value={created.api_key}
            aria-label="New operator key (shown once)"
            data-testid="operator-key-value"
          />
          <div className="aw-row">
            <button
              className="btn btn-outline"
              onClick={() => {
                setOpKey(created.api_key);
              }}
            >
              Use it as the decision credential in this tab
            </button>
            <button className="btn btn-outline" onClick={() => setCreated(null)}>
              I have stored it; hide it
            </button>
          </div>
          <p className="aw-note">{created.note}</p>
        </div>
      )}
    </div>
  );
}
