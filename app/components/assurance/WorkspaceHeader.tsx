'use client';

import { useState } from 'react';
import { describeOutcome, type Me } from '../../lib/assuranceApi';
import { signOut } from '../../lib/apiKey';
import {
  describeOrigin,
  ENVIRONMENT_LABEL,
  identityFromMe,
  KEY_TRANSPORT_NOTE,
  type OriginInfo,
} from '../../lib/workspaceIdentity';
import type { Panel } from './usePanel';
import styles from './workspace.module.css';

export const ASSURANCE_ORIGIN = describeOrigin(
  process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '',
  'NEXT_PUBLIC_ASSURANCE_API_URL',
);
export const PLATFORM_ORIGIN = describeOrigin(
  process.env.NEXT_PUBLIC_NEURALBRIDGE_API_URL || '',
  'NEXT_PUBLIC_NEURALBRIDGE_API_URL',
);

function Field({ label, children, testid }: { label: string; children: React.ReactNode; testid?: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd data-testid={testid}>{children}</dd>
    </div>
  );
}

export function OriginFields({ origin }: { origin: OriginInfo }) {
  return (
    <>
      <Field label="API origin" testid="ws-origin">
        {origin.configured ? <code>{origin.origin}</code> : <>none (<code>{origin.setting}</code> is not set in this build)</>}
      </Field>
      <Field label="Environment" testid="ws-environment">
        <span className={`${styles.tag} ${origin.keyTransport === 'cleartext' ? styles.tagWarn : ''}`}>
          {ENVIRONMENT_LABEL[origin.environment]}
        </span>
      </Field>
    </>
  );
}

// Who and where, on every workspace screen: the account and plan the API reported for the key in
// this tab, the origin that key is sent to, and which ledger the records come from. Nothing here is
// inferred: before the API has answered, each field says it is not known.
export default function WorkspaceHeader({
  surface,
  origin,
  me,
  apiKey,
  platformSession,
}: {
  surface: 'assurance' | 'console' | 'ai';
  origin: OriginInfo;
  /** `GET /v1/me` for the assurance API (assurance and console screens). */
  me?: Panel<Me>;
  apiKey: string;
  /** `GET /ai/session` for the platform API (the /ai screen): a tier, never an account. */
  platformSession?: { tier: string; loaded: boolean; failed: string | null };
}) {
  const [cleared, setCleared] = useState(false);

  let account: React.ReactNode;
  let plan: React.ReactNode;
  let ledger: React.ReactNode;
  let accountNote = '';

  if (!origin.configured) {
    account = plan = ledger = 'unknown: no API is configured, so nothing can answer';
  } else if (surface === 'ai') {
    account = 'not reported by this API (it returns a plan tier, not an account)';
    ledger = "tenant connections you bind; the shared demonstration database belongs to the operator, not to you";
    if (platformSession?.failed) plan = platformSession.failed;
    else if (platformSession?.loaded) plan = platformSession.tier;
    else plan = 'loading…';
  } else if (!apiKey) {
    account = 'no key in this tab';
    plan = 'free validator (no key)';
    ledger = 'none until a key is pasted';
  } else if (!me?.outcome || (me.loading && !me.good)) {
    account = plan = ledger = 'loading…';
  } else if (me.outcome.kind !== 'ok') {
    const d = describeOutcome(me.outcome);
    account = <strong>{d.heading}</strong>;
    plan = 'not known: the API did not return one';
    ledger = 'not known';
    accountNote = d.text;
  } else {
    const id = identityFromMe(me.outcome.data);
    account = (
      <>
        {id.accountLabel}
        {id.accountStatus ? ` · status ${id.accountStatus}` : ''}
        {id.accountSource ? ` · ${id.accountSource.replace('_', ' ')}` : ''}
      </>
    );
    plan = id.planLabel;
    ledger = id.ledger;
  }

  const onSignOut = () => {
    signOut();
    setCleared(true);
  };

  return (
    <section className={styles.identity} aria-label="Workspace identity" data-testid="workspace-identity" data-surface={surface}>
      <dl className={styles.identityGrid}>
        <Field label="Account" testid="ws-account">{account}</Field>
        <Field label="Plan" testid="ws-plan">{plan}</Field>
        <OriginFields origin={origin} />
        <Field label="Records shown" testid="ws-ledger">{ledger}</Field>
      </dl>
      {accountNote && <p className="aw-note" style={{ marginTop: '0.5rem' }}>{accountNote}</p>}
      <div className={styles.identityFoot}>
        <span>{KEY_TRANSPORT_NOTE[origin.keyTransport]}</span>
        <span>
          Kept in this tab only; never shown, logged or put in a URL.
        </span>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={onSignOut}
          data-testid="ws-signout"
        >
          Sign out of this tab
        </button>
        <span role="status" aria-live="polite" data-testid="ws-signout-status">
          {cleared ? 'Signed out: the key and operator credential were removed from this tab.' : ''}
        </span>
      </div>
    </section>
  );
}

// Demonstration or sample content must never look like a customer record.
export function DemoLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className={styles.demo} data-testid="demo-label">
      {children}
    </span>
  );
}
