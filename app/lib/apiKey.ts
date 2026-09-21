'use client';

import { useEffect, useState } from 'react';

// One API key, shared between /console and /ai in this browser tab.
//
// Security limits, stated plainly: this is sessionStorage, not an auth
// system. It is scoped to one browser tab (gone on tab close, never sent
// anywhere but the configured API host, never synced across devices or
// even other tabs of the same origin), and anything running in this page's
// JS context — a browser extension, a devtools session, an XSS bug
// elsewhere on the origin — can read it. It exists so a buyer who pastes
// their key once does not have to retype it when they move from a guided
// Console flow to /ai, not as a substitute for a real session/auth layer.
// Do not extend this pattern to anything more sensitive than an API key
// the buyer can already rotate from their own account.
export const API_KEY_STORAGE = 'nb-api-key';

// Earlier, pre-unification storage keys. Read once, on first mount, so a
// key someone already pasted into one surface keeps working after this
// change ships — never written to again.
const LEGACY_KEYS = ['nb-console-api-key', 'nb-ai-api-key'];

export function useSharedApiKey() {
  const [key, setKeyState] = useState('');

  useEffect(() => {
    try {
      let stored = window.sessionStorage.getItem(API_KEY_STORAGE) || '';
      if (!stored) {
        for (const legacy of LEGACY_KEYS) {
          const found = window.sessionStorage.getItem(legacy);
          if (found) {
            stored = found;
            window.sessionStorage.setItem(API_KEY_STORAGE, found);
            break;
          }
        }
      }
      setKeyState(stored);
    } catch {
      // sessionStorage can throw in a locked-down browser context (private
      // mode with site data blocked, some sandboxed iframes). The caller
      // still works, it just won't remember the key across a re-render.
    }
  }, []);

  const setKey = (value: string) => {
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
