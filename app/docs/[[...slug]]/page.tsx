import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import Link from 'next/link';
import { DOCS_NAV, listDocSlugs, loadDoc } from '../../lib/docs';
import DocsSidebar from '../../components/DocsSidebar';
import Breadcrumbs from '../../components/Breadcrumbs';
import { buildMetadata, docDescription } from '../../lib/seo';

export function generateStaticParams() {
  // `[]` is /docs itself: it has no markdown source, so it is rendered from DOCS_NAV below.
  return [{ slug: [] as string[] }, ...listDocSlugs()];
}

// Next 15+ hands route params over as a Promise, and Next 16 removed the synchronous access that
// 14 allowed: reading the slug straight off `params` yields undefined, which for this catch-all
// quietly renders the docs index for every URL (a 200 with a canonical of /docs/). Always await.
type DocParams = Promise<{ slug?: string[] }>;

// Markdown renders to bare HTML; two of its outputs fail keyboard and screen-reader use as they are:
//  - a code block that scrolls sideways needs a tab stop, so each <pre> gets tabindex="0";
//  - a task-list item is an <input type="checkbox"> with no label, so it is named by the item's own text.
const accessibleDocHtml = (html: string) =>
  html
    .replace(/<pre>/g, '<pre tabindex="0">')
    .replace(/<li><input disabled="" type="checkbox">([\s\S]*?)<\/li>/g, (_match, rest: string) => {
      const label = rest.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim().slice(0, 120).replace(/"/g, '&quot;');
      return '<li><input disabled="" type="checkbox" aria-label="' + label + '">' + rest + '</li>';
    });

const HOME_DESCRIPTION =
  'Industrial Autonomous Assurance documentation: getting started, each assurance engine, the capability table generated from the code, pricing as enforced, and platform status.';

// The same sentence, kept inside the 120-160 characters a search snippet shows.
const HOME_META_DESCRIPTION =
  'Industrial Autonomous Assurance documentation: getting started, each assurance engine, the generated capability table, pricing as enforced and platform status.';

export async function generateMetadata({ params }: { params: DocParams }): Promise<Metadata> {
  const { slug } = await params;
  if (!slug?.length) {
    return buildMetadata({ title: 'Documentation', description: HOME_META_DESCRIPTION, path: '/docs' });
  }
  const doc = loadDoc(slug);
  if (!doc) return { title: 'Documentation' };
  return buildMetadata({
    title: `${doc.title} | Docs`,
    description: docDescription(doc.description, doc.title),
    path: `/docs/${slug.join('/')}`,
  });
}

export default async function DocPage({ params }: { params: DocParams }) {
  const { slug } = await params;

  if (!slug?.length) {
    return (
      <main id="top">
        <section className="docs-layout">
          <div className="shell docs-shell">
            <DocsSidebar activeHref="/docs" editPath="app/lib/docs.ts" />
            <div className="docs-main">
            <Breadcrumbs trail={[{ name: 'Home', path: '/' }, { name: 'Docs', path: '/docs' }]} />
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
          <div className="docs-main">
            <Breadcrumbs trail={[{ name: 'Home', path: '/' }, { name: 'Docs', path: '/docs' }, { name: doc.title, path: activeHref }]} />
            <article className="docs-content" dangerouslySetInnerHTML={{ __html: accessibleDocHtml(doc.html) }} />
          </div>
        </div>
      </section>
    </main>
  );
}
