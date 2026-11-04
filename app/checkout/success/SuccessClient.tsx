'use client';

import RepoLink from '../../components/RepoLink';
import { useEffect, useRef, useState } from 'react';
import { QUICKSTART, SALES } from '../../lib/links';
import { API_KEY_STORAGE } from '../../lib/apiKey';
import { call, describeOutcome, type ApiOutcome, type Me } from '../../lib/assuranceApi';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

type KeyResponse = {
  api_key: string;
  tier: string;
  account_id: string;
  keep_this: string;
  use_it: { header: string; start_here: string };
};

// Mirrors the real contract in src/assurance/api/billing_routes.py exactly:
// POST /v1/checkout/complete with {session_id, claim_token} in the BODY returns 202 while
// Stripe's webhook is still in flight (poll again), 200 with the one-time key once the webhook
// has minted it, 403 when a key is staged but this browser does not hold its claim token
// (nothing is consumed), and 410 when it was already collected or has expired. Landing on this
// page proves only that a browser followed a Stripe redirect — it never mints anything itself,
// and entitlement comes only from the signed webhook.
//
// The Stripe redirect puts only the session id in the query string. The claim token is NOT in the
// URL (Stripe stores the success URL, so a token in it would be readable by anyone with Stripe
// access): POST /v1/checkout returned it to the browser that started checkout, and
// app/components/PricingPlans.tsx stored it in THAT TAB's sessionStorage under
// `nb-checkout-claim:<session_id>`. sessionStorage is per tab, so a different tab, browser or device
// has no token: it gets the 'claim' state below (the key is held; an operator discards it and
// re-issues). Whoever can read this tab's sessionStorage, or saw the reply to POST /v1/checkout,
// holds the token.
// The session id is removed from the address bar with history.replaceState as the very first thing
// the page does, before any network call, and is then held in memory only. The page is served with
// Referrer-Policy: no-referrer and Cache-Control: no-store (next.config.js).
const MAX_ATTEMPTS = 10;
const POLL_MS = 2000;

type Captured = { sessionId: string; claim: string };

// Keep in step with app/components/PricingPlans.tsx.
const CLAIM_STORAGE_PREFIX = 'nb-checkout-claim:';

function storedClaim(sessionId: string): string {
  try {
    return window.sessionStorage.getItem(`${CLAIM_STORAGE_PREFIX}${sessionId}`) || '';
  } catch {
    return '';
  }
}

// Module scope, not component state: React strict mode (development) runs the effect twice, and
// the second run would otherwise find the URL already stripped.
let captured: Captured | null = null;

function captureAndStripUrl(): Captured | null {
  try {
    const url = new URL(window.location.href);
    const sessionId = url.searchParams.get('session_id') || '';
    if (url.search || url.hash) {
      // Keep the entry's state: Next's router keeps its own bookkeeping in it.
      window.history.replaceState(window.history.state, '', url.pathname);
    }
    if (sessionId) captured = { sessionId, claim: storedClaim(sessionId) };
  } catch {
    /* an unparsable URL has nothing to capture */
  }
  return captured;
}

function savedKey(): string {
  try {
    return window.sessionStorage.getItem(API_KEY_STORAGE) || '';
  } catch {
    return '';
  }
}

// The plan, as the server reports it for a key: GET /v1/me. Nothing here is inferred from
// the tier word in the checkout reply or from what the pricing page said.
function PlanFromApi({ me, label }: { me: ApiOutcome<Me> | null; label: string }) {
  if (me === null) return <p className="pricing-note">Reading your plan from <code>GET /v1/me</code>…</p>;
  if (me.kind !== 'ok') {
    const d = describeOutcome(me);
    return (
      <p className="pricing-note" role="alert">
        Your key is saved, but your plan could not be read: {d.heading}. {d.text} {d.remedy}
      </p>
    );
  }
  const m = me.data;
  return (
    <div className="ai-card" data-testid={label}>
      <p style={{ fontWeight: 600, marginBottom: '0.35rem' }}>
        Your plan, as the API reports it for this key (<code>GET /v1/me</code>): {m.plan.name} ({m.tier})
        {m.account ? `, account ${m.account.status}` : ''}
      </p>
      {m.warning && <p style={{ fontSize: '0.85rem' }}>{m.warning}</p>}
      <p style={{ fontSize: '0.85rem', marginBottom: '0.25rem' }}>What it includes:</p>
      <ul style={{ fontSize: '0.85rem' }}>
        {m.plan.includes.map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
    </div>
  );
}

export default function CheckoutSuccessClient() {
  const [sessionId, setSessionId] = useState('');

  const [state, setState] = useState<
    'polling' | 'ready' | 'nokey' | 'error' | 'no-session' | 'no-api' | 'claim' | 'gone'
  >('polling');
  const [key, setKey] = useState<KeyResponse | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [copied, setCopied] = useState(false);
  const [problem, setProblem] = useState('');
  const [me, setMe] = useState<ApiOutcome<Me> | null>(null);
  const [saved, setSaved] = useState<{ key: string; me: ApiOutcome<Me> | null } | null>(null);
  // One poll loop per session id, even when React runs the effect twice (development
  // strict mode). The reply that carries the one-time key must never be dropped: the
  // server deletes the key when it hands it over, so a discarded 200 cannot be fetched again.
  const startedFor = useRef<string | null>(null);

  useEffect(() => {
    // First, before anything else: take the session id and claim token out of the address bar.
    const got = captureAndStripUrl();
    if (!got) {
      setState('no-session');
      return;
    }
    const { sessionId: sid, claim } = got;
    setSessionId(sid);
    if (!API_BASE) {
      setState('no-api');
      return;
    }
    if (startedFor.current === sid) return;
    startedFor.current = sid;

    const poll = async (n: number) => {
      try {
        // The id and token travel in the body of a POST: never in a URL, so never in a log,
        // a history entry or a Referer.
        const res = await fetch(`${API_BASE}/v1/checkout/complete`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ session_id: sid, claim_token: claim }),
          cache: 'no-store',
          referrerPolicy: 'no-referrer',
        });
        if (res.status === 200) {
          const data = (await res.json()) as KeyResponse;
          // Persist before anything else can fail: this tab's sessionStorage only, the same store
          // /console, /ai and /assurance read (see ../../lib/apiKey). That is a deliberate
          // trade: any script on this origin can read it, which is the same exposure as the key
          // sitting on this page, and it is gone when the tab closes; the workspace needs it to
          // open without a retype. Never localStorage, never a URL, never a cookie. If it
          // throws, the key shown below and its Copy button are the fallback.
          try {
            window.sessionStorage.setItem(API_KEY_STORAGE, data.api_key);
          } catch {
            /* sessionStorage blocked — copy/paste still works */
          }
          setKey(data);
          setState('ready');
          setMe(await call<Me>(API_BASE, data.api_key, '/v1/me'));
          return;
        }
        if (res.status === 403) {
          // A key is staged and this browser does not hold its claim token. Nothing was
          // consumed, and polling again cannot change that, so stop.
          setState('claim');
          return;
        }
        if (res.status === 410) {
          setState('gone');
          return;
        }
        if (res.status === 202) {
          if (n >= MAX_ATTEMPTS) {
            // Without a token in this tab the buyer cannot be told "collected already": the key
            // may well be held for the tab that started checkout. Say that instead.
            setState(claim ? 'nokey' : 'claim');
            return;
          }
          setAttempt(n + 1);
          setTimeout(() => poll(n + 1), POLL_MS);
          return;
        }
        setProblem(`The API answered HTTP ${res.status}.`);
        setState('error');
      } catch {
        setProblem('The API could not be reached from this browser.');
        setState('error');
      }
    };

    void poll(0);
  }, []);

  // When no key arrived, a key already saved in this tab is offered, with its plan read from the API.
  useEffect(() => {
    if (state !== 'nokey' && state !== 'error') return;
    const k = savedKey();
    if (!k) return;
    setSaved({ key: k, me: null });
    void call<Me>(API_BASE, k, '/v1/me').then((out) => setSaved({ key: k, me: out }));
  }, [state]);

  const copyKey = async () => {
    if (!key) return;
    try {
      await navigator.clipboard.writeText(key.api_key);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard blocked — the key is still selectable text */
    }
  };

  const hasFleetViews = me?.kind === 'ok' && me.data.plan.limits.machine_verification === true;

  return (
    <section className="section" style={{ paddingTop: '3.5rem', minHeight: '60vh' }}>
      <div className="shell" style={{ maxWidth: '60ch' }}>
        {state === 'no-session' && (
          <div className="section-head">
            <span className="eyebrow">Checkout</span>
            <h2>No checkout session found</h2>
            <p>
              This page expects a <code>session_id</code> from a Stripe redirect. If you reached this page any
              other way, start from <a href="/#pricing">pricing</a> instead.
            </p>
          </div>
        )}

        {state === 'no-api' && (
          <div className="section-head">
            <span className="eyebrow">Checkout</span>
            <h2>The API isn&apos;t reachable from this build</h2>
            <p>
              This marketing site was built without <code>NEXT_PUBLIC_ASSURANCE_API_URL</code> set, so it has
              nowhere to check for your key. If you did pay, your key is safe — the webhook minted it regardless
              of whether this page can reach the API right now.{' '}
              <a href={SALES}>Contact sales</a> with your receipt.
            </p>
          </div>
        )}

        {state === 'polling' && (
          <div className="section-head">
            <span className="eyebrow">Checkout</span>
            <h2>Confirming your payment&hellip;</h2>
            <p>
              Waiting for Stripe&apos;s webhook to mint your key (attempt {attempt + 1} of {MAX_ATTEMPTS}). This
              is usually a few seconds.
            </p>
          </div>
        )}

        {state === 'nokey' && (
          <div className="section-head" data-testid="checkout-nokey">
            <span className="eyebrow">Checkout</span>
            <h2>No key is waiting for this checkout</h2>
            <p>
              After {MAX_ATTEMPTS} checks the API holds no key for this session. Either Stripe&apos;s webhook has not
              reached it yet — if this persists, the webhook endpoint may be unreachable or misconfigured, which is a
              real operational problem and not a normal wait — or the key was <strong>already collected</strong>: it is
              shown once, then deleted from the staging store, so reloading this page cannot show it again. If you lost
              it, issue another with <code>POST /v1/keys</code> from a key you still hold. Otherwise{' '}
              <a href={SALES}>contact sales</a> with your session ID: <code>{sessionId}</code>
            </p>
          </div>
        )}

        {state === 'claim' && (
          <div className="section-head" data-testid="checkout-claim">
            <span className="eyebrow">Checkout</span>
            <h2>A key is waiting, but this browser can&apos;t collect it</h2>
            <p>
              Your payment went through and a key is held for you, but this tab does not hold the claim
              token that proves it started the checkout. The token is kept only in the tab that
              started checkout (session storage is per tab), never in the address, and never by Stripe, so a
              different tab, browser or device cannot collect the key. Nothing was collected: the key is still
              held (for up to 24 hours). <a href={SALES}>Contact sales</a> with your session ID{' '}
              <code>{sessionId}</code> and an operator will discard the held key and issue you a new one.
            </p>
          </div>
        )}

        {state === 'gone' && (
          <div className="section-head" data-testid="checkout-gone">
            <span className="eyebrow">Checkout</span>
            <h2>This key has already been collected</h2>
            <p>
              Your payment completed, but no key is waiting any more: it was collected already, it expired (a
              key is held for 24 hours), or it was lost in a restore. It is shown once and cannot be shown
              again. If you did not collect it yourself, treat it as exposed. If you hold another key for this
              account, issue a new one with <code>POST /v1/keys</code>; otherwise{' '}
              <a href={SALES}>contact sales</a> with your session ID <code>{sessionId}</code> and an operator
              will issue a new key and revoke the old.
            </p>
          </div>
        )}

        {state === 'error' && (
          <div className="section-head" data-testid="checkout-error">
            <span className="eyebrow">Checkout</span>
            <h2>Could not check for your key</h2>
            <p>
              {problem} Nothing was learned about your payment from this. <a href={SALES}>Contact sales</a> with your
              session ID: <code>{sessionId}</code>
            </p>
          </div>
        )}

        {(state === 'nokey' || state === 'error') && saved && (
          <div className="ai-card" data-testid="checkout-saved-key" style={{ marginTop: '1.5rem' }}>
            <p style={{ fontWeight: 600, marginBottom: '0.35rem' }}>A key is already saved in this browser tab</p>
            <PlanFromApi me={saved.me} label="checkout-saved-plan" />
            {saved.me?.kind === 'ok' && (
              <>
                <p className="pricing-note">
                  {saved.me.data.plan.name} ({saved.me.data.tier}) — read from the API with the saved key. The key
                  itself is not shown again.
                </p>
                <a className="btn btn-primary" href="/assurance">
                  Open your workspace
                </a>
              </>
            )}
          </div>
        )}

        {state === 'ready' && key && (
          <div>
            <div className="section-head">
              <span className="eyebrow">Payment confirmed</span>
              <h2>Your {key.tier === 'register' ? 'Register' : key.tier === 'cell' ? 'Cell' : key.tier} key</h2>
              <p>{key.keep_this}</p>
            </div>
            <div className="hero-code" data-testid="issued-key" style={{ fontSize: '0.95rem', wordBreak: 'break-all' }}>
              {key.api_key}
            </div>
            <div className="hero-actions" style={{ marginTop: '1rem' }}>
              <button className="btn btn-secondary" onClick={copyKey}>
                {copied ? 'Copied' : 'Copy key'}
              </button>
            </div>
            <p className="pricing-note" style={{ marginTop: '1rem' }}>
              This tab has saved the key (session storage only, gone when the tab closes) so the workspace opens with
              it. Account ID <code>{key.account_id}</code>. Use it elsewhere as <code>{key.use_it.header}: {'<your key>'}</code>.
            </p>

            <div style={{ marginTop: '1.5rem' }}>
              <PlanFromApi me={me} label="checkout-plan" />
            </div>

            <div className="section-head" style={{ marginTop: '2rem' }}>
              <span className="eyebrow">Next</span>
              <h3 style={{ marginBottom: '0.25rem' }}>Open your workspace</h3>
            </div>
            <div data-testid="checkout-next">
              <p style={{ fontSize: '0.9rem' }}>
                The workspace reads your fleet, your change-assurance cases and your plan from the API with this key.
                {me?.kind === 'ok' && !hasFleetViews && (
                  <>
                    {' '}
                    Your plan does not include machine verification, so the fleet and change-assurance views need the
                    Cell plan: they will show the server&apos;s refusal and its remedy, not a fleet. The plan panel and
                    the Article 14 register flows below work on your plan.
                  </>
                )}
                {me?.kind === 'ok' && hasFleetViews && (
                  <> A new account has no machines yet: it will say so, and show how to enrol the first.</>
                )}
              </p>
              <div className="hero-actions">
                <a className="btn btn-primary" href="/assurance">
                  Open your workspace
                </a>
              </div>
            </div>

            <div className="section-head" style={{ marginTop: '2.5rem' }}>
              <h3 style={{ marginBottom: '0.25rem' }}>Also available with this key</h3>
            </div>
            <div style={{ display: 'grid', gap: '1rem', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))' }}>
              <div className="ai-card">
                <p style={{ fontWeight: 600, marginBottom: '0.35rem' }}>Open your first Register case</p>
                <p style={{ fontSize: '0.85rem' }}>
                  <a href="/console#first-case">Console&apos;s guided &ldquo;First Register case&rdquo; flow</a>{' '}
                  already has this key pasted in (this tab&apos;s session storage only) and calls the real{' '}
                  <code>POST /v1/cases/&#123;case_id&#125;/signal</code> from your browser — no shell needed. Prefer
                  curl? The exact command is in{' '}
                  <RepoLink path="/blob/main/docs/buyer-journey.md" plain>
                    docs/buyer-journey.md
                  </RepoLink>{' '}
                  (see also <a href={QUICKSTART}>the quickstart</a> for the rest of the API).
                </p>
              </div>
              <div className="ai-card">
                <p style={{ fontWeight: 600, marginBottom: '0.35rem' }}>Use /ai with this key</p>
                <p style={{ fontSize: '0.85rem' }}>
                  <a href="/ai">/ai</a> reads the same saved key (plain <code>X-API-Key</code>, this browser tab only,
                  never sent anywhere else). That unlocks the write path: propose a write, approve it, get an
                  execution receipt.
                </p>
              </div>
              {hasFleetViews && (
                <div className="ai-card">
                  <p style={{ fontWeight: 600, marginBottom: '0.35rem' }}>Cell: verify a machine run</p>
                  <p style={{ fontSize: '0.85rem' }}>
                    Your plan includes machine verification.{' '}
                    <a href="/console#cell-verify">Open the Console&apos;s machine-verification flow</a> with this key
                    already pasted in.
                  </p>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
