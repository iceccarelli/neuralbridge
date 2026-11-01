import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import Link from 'next/link';
import { DOCS_NAV, listDocSlugs, loadDoc } from '../../lib/docs';
import DocsSidebar from '../../components/DocsSidebar';

export function generateStaticParams() {
  // `[]` is /docs itself: it has no markdown source, so it is rendered from DOCS_NAV below.
  return [{ slug: [] as string[] }, ...listDocSlugs()];
}

// Next 15+ hands route params over as a Promise, and Next 16 removed the synchronous access that
// 14 allowed: reading the slug straight off `params` yields undefined, which for this catch-all
// quietly renders the docs index for every URL (a 200 with a canonical of /docs/). Always await.
type DocParams = Promise<{ slug?: string[] }>;

const HOME_DESCRIPTION =
  'Industrial Autonomous Assurance documentation: getting started, each assurance engine, the capability table generated from the code, pricing as enforced, and platform status.';

export async function generateMetadata({ params }: { params: DocParams }): Promise<Metadata> {
  const { slug } = await params;
  if (!slug?.length) {
    return {
      title: 'Documentation | Industrial Autonomous Assurance',
      description: HOME_DESCRIPTION,
      alternates: { canonical: '/docs' },
    };
  }
  const doc = loadDoc(slug);
  if (!doc) return { title: 'Documentation' };
  return {
    title: `${doc.title} | Docs | Industrial Autonomous Assurance`,
    description: doc.description || `${doc.title}: Industrial Autonomous Assurance documentation.`,
    alternates: { canonical: `/docs/${slug.join('/')}` },
  };
}

export default async function DocPage({ params }: { params: DocParams }) {
  const { slug } = await params;

  if (!slug?.length) {
    return (
      <main id="top">
        <section className="docs-layout">
          <div className="shell docs-shell">
            <DocsSidebar activeHref="/docs" editPath="app/lib/docs.ts" />
            <article className="docs-content">
              <h1>Documentation</h1>
              <p>{HOME_DESCRIPTION}</p>
              <ul>
                {DOCS_NAV.filter((item) => item.href !== '/docs').map((item) => (
                  <li key={item.href}>
                    <Link href={item.href}>{item.label}</Link>
                    {item.children && (
                      <ul>
                        {item.children.map((child) => (
                          <li key={child.href}>
                            <Link href={child.href}>{child.label}</Link>
                          </li>
                        ))}
                      </ul>
                    )}
                  </li>
                ))}
              </ul>
            </article>
          </div>
        </section>
      </main>
    );
  }

  const doc = loadDoc(slug);
  if (!doc) notFound();

  const activeHref = `/docs/${slug.join('/')}`;

  return (
    <main id="top">
      <section className="docs-layout">
        <div className="shell docs-shell">
          <DocsSidebar activeHref={activeHref} editPath={doc.editPath} />
          <article className="docs-content" dangerouslySetInnerHTML={{ __html: doc.html }} />
        </div>
      </section>
    </main>
  );
}
