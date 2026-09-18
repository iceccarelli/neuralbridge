'use client';

import { useState } from 'react';

// No backend exists to receive this yet (see the pricing section's honesty
// note about what is and isn't deployed), so this widget does not claim to
// send anything anywhere. It only confirms the click locally. Swap the
// no-op in `submit` for a real endpoint once one exists.
export default function Feedback() {
  const [open, setOpen] = useState(false);
  const [answer, setAnswer] = useState<'yes' | 'no' | null>(null);

  const submit = (value: 'yes' | 'no') => {
    setAnswer(value);
  };

  return (
    <div className="feedback-widget">
      {!open ? (
        <button className="feedback-trigger" onClick={() => setOpen(true)}>
          ☆ Feedback
        </button>
      ) : (
        <div className="feedback-panel">
          <button className="feedback-close" aria-label="Close" onClick={() => setOpen(false)}>✕</button>
          {answer === null ? (
            <>
              <p>Was this page helpful?</p>
              <div className="feedback-buttons">
                <button className="btn btn-secondary" onClick={() => submit('yes')}>Yes</button>
                <button className="btn btn-secondary" onClick={() => submit('no')}>No</button>
              </div>
            </>
          ) : (
            <p>
              Thanks — this isn&apos;t wired to anywhere yet, so nothing was sent. Real feedback:{' '}
              <a href="https://github.com/iceccarelli/neuralbridge/issues/new" target="_blank" rel="noreferrer">
                open an issue
              </a>.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
