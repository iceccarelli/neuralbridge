'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { call, keepsLastGood, type ApiOutcome } from '../../lib/assuranceApi';

export const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

// Data older than this is labelled as possibly out of date. It is the age of what this
// browser last received, not a statement about the server.
export const STALE_AFTER_MS = 5 * 60_000;

export type Panel<T> = {
  /** The latest answer, or null before the first one (including "no key yet"). */
  outcome: ApiOutcome<T> | null;
  /**
   * The last good data, kept only while it is honest to show: after a transport failure
   * or a 5xx. After a 401/402/403/404 the previous data may no longer be yours to see.
   */
  good: { data: T; at: number } | null;
  loading: boolean;
  reload: () => Promise<void>;
};

// One independent request per panel: a failure in one never touches another. A change of
// key discards everything held for the old key, and a late answer for an old key or path
// is ignored.
export function usePanel<T>(apiKey: string, path: string | null): Panel<T> {
  const [outcome, setOutcome] = useState<ApiOutcome<T> | null>(null);
  const [good, setGood] = useState<{ data: T; at: number } | null>(null);
  const [loading, setLoading] = useState(false);
  const seq = useRef(0);
  const goodRef = useRef<{ data: T; at: number } | null>(null);

  const reload = useCallback(async () => {
    const id = ++seq.current;
    if (!API_BASE || !path) return;
    setLoading(true);
    const out = await call<T>(API_BASE, apiKey, path);
    if (id !== seq.current) return; // a newer request, or a different key, owns the panel now
    setOutcome(out);
    if (out.kind === 'ok') {
      goodRef.current = { data: out.data, at: out.at };
    } else if (!keepsLastGood(out)) {
      goodRef.current = null;
    }
    setGood(goodRef.current);
    setLoading(false);
  }, [apiKey, path]);

  useEffect(() => {
    seq.current++; // invalidate anything in flight for the previous key or path
    goodRef.current = null;
    setGood(null);
    setLoading(false);
    if (!API_BASE) {
      setOutcome({ kind: 'unconfigured' });
      return;
    }
    setOutcome(null);
    if (!apiKey || !path) return;
    // A short debounce so typing a key does not fire a request per keystroke.
    const t = setTimeout(() => void reload(), 250);
    return () => clearTimeout(t);
  }, [apiKey, path, reload]);

  return { outcome, good, loading, reload };
}

// Re-renders every `ms` and when the tab becomes visible again, so ages stay true.
export function useNow(ms = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const tick = () => setNow(Date.now());
    const t = setInterval(tick, ms);
    document.addEventListener('visibilitychange', tick);
    return () => {
      clearInterval(t);
      document.removeEventListener('visibilitychange', tick);
    };
  }, [ms]);
  return now;
}

export function clock(at: number): string {
  return new Date(at).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function agoText(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 45) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  return `${h} h ago`;
}
