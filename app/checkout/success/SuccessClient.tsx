'use client';

import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { SALES } from '../../lib/links';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

type KeyResponse = {
  api_key: string;
  tier: string;
  account_id: string;
  keep_this: string;
  use_it: { header: string; start_here: string };
};

// Mirrors the real contract in src/assurance/api/billing_routes.py exactly:
// GET /v1/checkout/complete?session_id=... returns 202 while Stripe's
// webhook is still in flight (poll again), or 200 with the one-time key once
// the webhook has minted it. Landing on this page proves only that a browser
// followed a Stripe redirect — it never mints anything itself.
const MAX_ATTEMPTS = 10;
const POLL_MS = 2000;

export default function CheckoutSuccessClient() {
  const params = useSearchParams();
  const sessionId = params.get('session_id');

  const [state, setState] = useState<'polling' | 'ready' | 'failed' | 'no-session' | 'no-api'>('polling');
  const [key, setKey] = useState<KeyResponse | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [copied, setCopied] = useState(false);
  const cancelled = useRef(false);

  useEffect(() => {
    if (!sessionId) {
      setState('no-session');
      return;
    }
    if (!API_BASE) {
      setState('no-api');
      return;
    }
    cancelled.current = false;

    const poll = async (n: number) => {
      if (cancelled.current) return;
      try {
        const res = await fetch(`${API_BASE}/v1/checkout/complete?session_id=${encodeURIComponent(sessionId)}`);
        if (res.status === 200) {
          const data = (await res.json()) as KeyResponse;
          if (!cancelled.current) {
            setKey(data);
            setState('ready');
          }
          return;
        }
        if (res.status === 202) {
          if (n >= MAX_ATTEMPTS) {
            if (!cancelled.current) setState('failed');
            return;
          }
          setAttempt(n + 1);
          setTimeout(() => poll(n + 1), POLL_MS);
          return;
        }
        if (!cancelled.current) setState('failed');
      } catch {
        if (!cancelled.current) setState('failed');
      }
    };

    poll(0);
    return () => {
      cancelled.current = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

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
              <a href={SALES} target="_blank" rel="noreferrer">Contact sales</a> with your receipt.
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

        {state === 'failed' && (
          <div className="section-head">
            <span className="eyebrow">Checkout</span>
            <h2>Still waiting on the webhook</h2>
            <p>
              Payment is confirmed by Stripe&apos;s webhook, which hasn&apos;t arrived yet after {MAX_ATTEMPTS}{' '}
              checks. If this persists, the webhook endpoint may be unreachable or misconfigured &mdash; that is a
              real operational problem, not a normal wait.{' '}
              <a href={SALES} target="_blank" rel="noreferrer">Contact sales</a> with your session ID:{' '}
              <code>{sessionId}</code>
            </p>
          </div>
        )}

        {state === 'ready' && key && (
          <div>
            <div className="section-head">
              <span className="eyebrow">Payment confirmed</span>
              <h2>Your {key.tier === 'register' ? 'Register' : 'Cell'} key</h2>
              <p>{key.keep_this}</p>
            </div>
            <div className="hero-code" style={{ fontSize: '0.95rem', wordBreak: 'break-all' }}>
              {key.api_key}
            </div>
            <div className="hero-actions" style={{ marginTop: '1rem' }}>
              <button className="btn btn-primary" onClick={copyKey}>
                {copied ? 'Copied' : 'Copy key'}
              </button>
            </div>
            <p className="pricing-note" style={{ marginTop: '1.5rem' }}>
              Use it: <code>{key.use_it.header}: {'<your key>'}</code> against{' '}
              <code>{key.use_it.start_here}</code> to confirm it works. Account ID <code>{key.account_id}</code>.
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
