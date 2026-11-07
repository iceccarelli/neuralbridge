// Every browser-held credential or credential-adjacent identifier this site writes, in one place,
// so that "sign out" removes all of them and nothing else has to remember what exists. Pure (the
// storage is passed in) so it can be exercised under node with a fake storage.
//
// What each one is, and where it goes, is listed on /privacy. All of them are sessionStorage: one
// browser tab, gone when the tab closes. None is ever logged, placed in a URL, or rendered.

export const API_KEY_STORAGE = 'nb-api-key';
// Earlier, pre-unification storage keys. Read once so a key pasted into one surface keeps working,
// and DELETED as soon as it has been carried over (or found to be redundant): a second copy of a
// key in storage is exposure with no benefit.
export const LEGACY_KEY_STORAGE = ['nb-console-api-key', 'nb-ai-api-key'] as const;
export const DECISION_CREDENTIAL_STORAGE = 'nb-assurance-decision-credential';
export const AI_ACTOR_STORAGE = 'nb-ai-actor';
export const AI_SESSION_STORAGE = 'nb-ai-session';
// `nb-checkout-claim:<stripe session id>` holds a one-time claim token for the key purchased in this tab.
export const CHECKOUT_CLAIM_PREFIX = 'nb-checkout-claim:';

/** Fired on `window` after credentials were cleared, so mounted components drop what they hold in memory. */
export const CREDENTIALS_CLEARED_EVENT = 'workspace-credentials-cleared';

export type KeyValueStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'key' | 'length'>;

/** Keys must travel in an HTTP header: trim what a paste adds (spaces, a newline) and nothing else. */
export function normaliseKey(value: string): string {
  return value.trim();
}

/**
 * The stored key, adopting a legacy one once. Every legacy copy is removed afterwards, whether or not
 * it was needed. Returns '' when nothing is stored. Never throws (blocked storage reads as empty).
 */
export function readStoredKey(storage: KeyValueStorage): string {
  try {
    let stored = storage.getItem(API_KEY_STORAGE) || '';
    for (const legacy of LEGACY_KEY_STORAGE) {
      const found = storage.getItem(legacy);
      if (found && !stored) {
        stored = found;
        storage.setItem(API_KEY_STORAGE, found);
      }
      if (found !== null) storage.removeItem(legacy);
    }
    return stored;
  } catch {
    return '';
  }
}

/** Remove every credential this site holds in `storage`. Returns the storage keys it removed. */
export function clearCredentials(storage: KeyValueStorage): string[] {
  const removed: string[] = [];
  try {
    const names: string[] = [];
    for (let i = 0; i < storage.length; i++) {
      const k = storage.key(i);
      if (k) names.push(k);
    }
    for (const k of names) {
      if (
        k === API_KEY_STORAGE ||
        k === DECISION_CREDENTIAL_STORAGE ||
        k === AI_ACTOR_STORAGE ||
        k === AI_SESSION_STORAGE ||
        (LEGACY_KEY_STORAGE as readonly string[]).includes(k) ||
        k.startsWith(CHECKOUT_CLAIM_PREFIX)
      ) {
        storage.removeItem(k);
        removed.push(k);
      }
    }
  } catch {
    /* blocked storage holds nothing to clear */
  }
  return removed;
}
