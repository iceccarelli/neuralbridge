'use client';

import { useEffect, useState } from 'react';

const STORAGE_KEY = 'iaa-cookie-choice';

type Choice = 'accepted' | 'declined';

function readChoice(): Choice | null {
  try {
    const v = window.localStorage.getItem(STORAGE_KEY);
    return v === 'accepted' || v === 'declined' ? v : null;
  } catch {
    return null;
  }
}

function writeChoice(choice: Choice) {
  try {
    window.localStorage.setItem(STORAGE_KEY, choice);
  } catch {
    // Private browsing or blocked storage: the choice just won't persist.
  }
}

// This site sets no cookies and runs no analytics or trackers today — checked
// against the actual codebase, not asserted. The banner still exists because
// the choice needs to be ready before that changes, and because "Decline" is
// not an afterthought here. The one thing this writes is a first-party
// localStorage flag recording the choice itself, not a tracking cookie.
export default function CookieConsent() {
  const [visible, setVisible] = useState(false);
  const [customizeOpen, setCustomizeOpen] = useState(false);

  useEffect(() => {
    setVisible(readChoice() === null);
  }, []);

  const decide = (choice: Choice) => {
    writeChoice(choice);
    setVisible(false);
    setCustomizeOpen(false);
  };

  useEffect(() => {
    const openHandler = () => setVisible(true);
    window.addEventListener('iaa:open-cookie-preferences', openHandler);
    return () => window.removeEventListener('iaa:open-cookie-preferences', openHandler);
  }, []);

  if (!visible) return null;

  return (
    <div className="cookie-banner" role="dialog" aria-label="Cookie preferences" aria-live="polite">
      <div className="cookie-banner-inner">
        {!customizeOpen ? (
          <>
            <p>
              This site does not use tracking or analytics cookies today. We&apos;d still like your preference on
              record before that ever changes — see{' '}
              <a href="/privacy">what this site actually collects</a>.
            </p>
            <div className="cookie-actions">
              <button className="btn btn-outline" onClick={() => setCustomizeOpen(true)}>Customize</button>
              <button className="btn btn-outline" onClick={() => decide('declined')}>Decline</button>
              <button className="btn btn-primary" onClick={() => decide('accepted')}>Accept</button>
            </div>
          </>
        ) : (
          <>
            <p>
              <strong>Strictly necessary (always on):</strong> one local preference flag recording this choice.
              Nothing is sent to a server, nothing is shared. <strong>Analytics / marketing:</strong> not present on
              this site as of this build — there is nothing to opt into yet.
            </p>
            <div className="cookie-actions">
              <button className="btn btn-outline" onClick={() => decide('declined')}>Confirm: decline everything optional</button>
              <button className="btn btn-primary" onClick={() => decide('accepted')}>Confirm: accept when it exists</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
