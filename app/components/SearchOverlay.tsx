'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { SEARCH_INDEX, type SearchGroup } from '../lib/search-index';

const GROUPS: SearchGroup[] = ['Products', 'Solutions', 'Docs'];

export default function SearchOverlay({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setQuery('');
      const t = setTimeout(() => inputRef.current?.focus(), 20);
      return () => clearTimeout(t);
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    const matches = q
      ? SEARCH_INDEX.filter(
          (e) => e.title.toLowerCase().includes(q) || e.blurb.toLowerCase().includes(q),
        )
      : SEARCH_INDEX;
    return GROUPS.map((group) => ({ group, items: matches.filter((m) => m.group === group) })).filter(
      (g) => g.items.length > 0,
    );
  }, [query]);

  if (!open) return null;

  return (
    <div className="search-overlay" role="dialog" aria-modal="true" aria-label="Search">
      <button className="search-overlay-scrim" aria-label="Close search" onClick={onClose} />
      <div className="search-panel">
        <div className="search-input-row">
          <span className="search-icon" aria-hidden>⌕</span>
          <input
            ref={inputRef}
            className="search-input"
            type="text"
            placeholder="I'm looking for…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <button className="search-close" onClick={onClose} aria-label="Close">✕</button>
        </div>

        {results.length === 0 ? (
          <p className="search-empty">No matches on this page. Try the README, linked below.</p>
        ) : (
          <div className="search-results">
            {results.map((g) => (
              <div className="search-group" key={g.group}>
                <h4>{g.group}</h4>
                {g.items.map((item) => (
                  <a
                    key={item.title}
                    className="search-result"
                    href={item.href}
                    target={item.external ? '_blank' : undefined}
                    rel={item.external ? 'noreferrer' : undefined}
                    onClick={onClose}
                  >
                    <span className="search-result-title">{item.title}</span>
                    <span className="search-result-blurb">{item.blurb}</span>
                    <span className="search-result-pills">
                      <span className="search-pill">{item.group}</span>
                      {item.external && <span className="search-pill">Docs</span>}
                    </span>
                  </a>
                ))}
              </div>
            ))}
          </div>
        )}

        <p className="search-note">
          This searches this page's own sections and the repository's real docs — not a hosted index yet.
        </p>
      </div>
    </div>
  );
}
