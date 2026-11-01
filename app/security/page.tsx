import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import RepoLink from '../components/RepoLink';
import { loadRootDoc } from '../lib/docs';

export const metadata: Metadata = {
  title: 'Security | Industrial Autonomous Assurance',
  description: 'How to report a vulnerability — the real reporting address and what to include, not a GitHub redirect.',
  alternates: { canonical: '/security' },
  openGraph: {
    title: 'Security | Industrial Autonomous Assurance',
    description: 'How to report a vulnerability in this codebase.',
    url: '/security',
    type: 'website',
  },
};

export default function SecurityPage() {
  const doc = loadRootDoc('SECURITY.md', 'Security');
  if (!doc) notFound();

  return (
    <main id="top">
      <section className="section" style={{ paddingTop: '3rem' }}>
        <div className="shell docs-standalone">
          <article className="docs-content" dangerouslySetInnerHTML={{ __html: doc.html }} />
          <RepoLink path={`/blob/main/${doc.editPath}`} className="docs-nav-edit">
            Edit this page on GitHub ↗
          </RepoLink>
        </div>
      </section>
    </main>
  );
}
