import type { ReactNode } from 'react';

// Renders a plain string in which `backticked` spans are code. Copy lives in data modules as plain strings
// (so tests and the search index can read it); this is the only place those spans become markup.
export default function Inline({ text }: { text: string }) {
  const parts: ReactNode[] = text.split('`').map((part, i) => (i % 2 === 1 ? <code key={i}>{part}</code> : part));
  return <>{parts}</>;
}
