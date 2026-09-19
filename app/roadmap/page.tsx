import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { REPO } from '../lib/links';
import { loadRootDoc } from '../lib/docs';

export const metadata: Metadata = {
  title: 'Roadmap | Industrial Autonomous Assurance',
  description: 'What is shipped versus what is planned — nothing marked done unless it is gated in code and covered by tests.',
  alternates: { canonical: '/roadmap' },
  openGraph: {
    title: 'Roadmap | Industrial Autonomous Assurance',
    description: 'Shipped, evolving, and planned — kept to the same honesty standard as the rest of this repository.',
    url: '/roadmap',
    type: 'website',
  },
};

export default function RoadmapPage() {
  const doc = loadRootDoc('ROADMAP.md', 'Roadmap');
  if (!doc) notFound();

  return (
    <main id="top">
      <section className="section" style={{ paddingTop: '3rem' }}>
        <div className="shell docs-standalone">
          <article className="docs-content" dangerouslySetInnerHTML={{ __html: doc.html }} />
          <a className="docs-nav-edit" href={`${REPO}/blob/main/${doc.editPath}`} target="_blank" rel="noreferrer">
            Edit this page on GitHub ↗
          </a>
        </div>
      </section>
    </main>
  );
}
