import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import Link from 'next/link';
import { DOCS_NAV, listDocSlugs, loadDoc } from '../../lib/docs';
import { REPO } from '../../lib/links';

export function generateStaticParams() {
  return listDocSlugs();
}

export function generateMetadata({ params }: { params: { slug?: string[] } }): Metadata {
  const doc = loadDoc(params.slug);
  if (!doc) return { title: 'Documentation' };
  return {
    title: `${doc.title} | Docs | Industrial Autonomous Assurance`,
    alternates: { canonical: `/docs/${(params.slug ?? []).join('/')}` },
  };
}

export default function DocPage({ params }: { params: { slug?: string[] } }) {
  const doc = loadDoc(params.slug);
  if (!doc) notFound();

  const activeHref = `/docs/${(params.slug ?? []).join('/')}`.replace(/\/$/, '') || '/docs';

  return (
    <main id="top">
      <section className="docs-layout">
        <div className="shell docs-shell">
          <nav className="docs-sidebar" aria-label="Documentation">
            {DOCS_NAV.map((item) => (
              <div key={item.href} className="docs-nav-group">
                <Link
                  href={item.href}
                  className={`docs-nav-link ${activeHref === item.href ? 'active' : ''}`}
                >
                  {item.label}
                </Link>
                {item.children && (
                  <div className="docs-nav-children">
                    {item.children.map((child) => (
                      <Link
                        key={child.href}
                        href={child.href}
                        className={`docs-nav-link docs-nav-child ${activeHref === child.href ? 'active' : ''}`}
                      >
                        {child.label}
                      </Link>
                    ))}
                  </div>
                )}
              </div>
            ))}
            <a
              className="docs-nav-link docs-nav-edit"
              href={`${REPO}/blob/main/${doc.editPath}`}
              target="_blank"
              rel="noreferrer"
            >
              Edit this page on GitHub ↗
            </a>
          </nav>

          <article className="docs-content" dangerouslySetInnerHTML={{ __html: doc.html }} />
        </div>
      </section>
    </main>
  );
}
