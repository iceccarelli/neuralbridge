'use client';

import { useEffect, useState } from 'react';
import {
  API_KEY_STORAGE,
  clearCredentials,
  CREDENTIALS_CLEARED_EVENT,
  normaliseKey,
  readStoredKey,
} from './credentials';

export { API_KEY_STORAGE };

// One API key, shared between /console, /ai and /assurance in this browser tab.
//
// Security limits, stated plainly: this is sessionStorage, not an auth
// system. It is scoped to one browser tab (gone on tab close, never sent
// anywhere but the configured API host, never synced across devices or
// even other tabs of the same origin), and anything running in this page's
// JS context — a browser extension, a devtools session, an XSS bug
// elsewhere on the origin — can read it. It exists so a buyer who pastes
// their key once does not have to retype it when they move between the
// workspace screens, not as a substitute for a real session/auth layer.
// Do not extend this pattern to anything more sensitive than an API key
// the buyer can already rotate from their own account.
//
// The key is never rendered (the field is type=password), logged, put in a URL, or kept
// anywhere but this store and the component state below. `signOut()` removes every
// credential the site holds (see ./credentials) and tells every mounted hook to forget it.

const SYNC = 'nb-api-key-changed';

/** Sign out of this tab: clear every stored credential and tell mounted components to drop theirs. */
export function signOut(): string[] {
  let removed: string[] = [];
  try {
    removed = clearCredentials(window.sessionStorage);
  } catch {
    /* storage blocked: only the in-memory copies exist */
  }
  window.dispatchEvent(new Event(CREDENTIALS_CLEARED_EVENT));
  window.dispatchEvent(new Event(SYNC));
  return removed;
}

export function useSharedApiKey() {
  const [key, setKeyState] = useState('');

  useEffect(() => {
    const read = () => {
      try {
        setKeyState(readStoredKey(window.sessionStorage));
      } catch {
        // sessionStorage can throw in a locked-down browser context (private
        // mode with site data blocked, some sandboxed iframes). The caller
        // still works, it just won't remember the key across a re-render.
      }
    };
    read();
    const cleared = () => setKeyState('');
    window.addEventListener(SYNC, read);
    window.addEventListener(CREDENTIALS_CLEARED_EVENT, cleared);
    return () => {
      window.removeEventListener(SYNC, read);
      window.removeEventListener(CREDENTIALS_CLEARED_EVENT, cleared);
    };
  }, []);

  const setKey = (raw: string) => {
    const value = normaliseKey(raw);
    setKeyState(value);
    try {
      if (value) window.sessionStorage.setItem(API_KEY_STORAGE, value);
      else window.sessionStorage.removeItem(API_KEY_STORAGE);
    } catch {
      // Same as above — best effort only.
    }
  };

  return { key, setKey };
}
