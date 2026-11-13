import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import Link from 'next/link';
import { DOCS_NAV, listDocSlugs, loadDoc } from '../../lib/docs';
import DocsSidebar from '../../components/DocsSidebar';
import Breadcrumbs from '../../components/Breadcrumbs';
import { buildMetadata, docDescription } from '../../lib/seo';
import VisualDiagram from '../../components/VisualDiagram';
import { DOCS_VISUAL_BY_PATH } from '../../lib/visuals';

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
    // a wide markdown table scrolls inside its own keyboard-focusable region instead of widening the page
    .replace(/<table>/g, '<div class="docs-table-scroll" tabindex="0" role="region" aria-label="Table, scrolls sideways"><table>')
    .replace(/<\/table>/g, '</table></div>')
    .replace(/<li><input disabled="" type="checkbox">([\s\S]*?)<\/li>/g, (_match, rest: string) => {
      const label = rest.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim().slice(0, 120).replace(/"/g, '&quot;');
      return '<li><input disabled="" type="checkbox" aria-label="' + label + '">' + rest + '</li>';
    });

const HOME_DESCRIPTION =
  'NeuralBridge documentation for Industrial Autonomous Assurance: getting started, each assurance engine, the capability table generated from the code, pricing as enforced, and platform status.';

// The same sentence, kept inside the 120-160 characters a search snippet shows.
const HOME_META_DESCRIPTION =
  'NeuralBridge documentation for Industrial Autonomous Assurance: getting started, each engine, the capability table, pricing as enforced and platform status.';

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
  const visualSlug = DOCS_VISUAL_BY_PATH[activeHref];
  const fullHtml = accessibleDocHtml(doc.html);
  const firstParaEnd = fullHtml.indexOf('</p>');
  const leadHtml = visualSlug && firstParaEnd !== -1 ? fullHtml.slice(0, firstParaEnd + 4) : fullHtml;
  const restHtml = visualSlug && firstParaEnd !== -1 ? fullHtml.slice(firstParaEnd + 4) : '';

  return (
    <main id="top">
      <section className="docs-layout">
        <div className="shell docs-shell">
          <DocsSidebar activeHref={activeHref} editPath={doc.editPath} />
          <div className="docs-main">
            <Breadcrumbs trail={[{ name: 'Home', path: '/' }, { name: 'Docs', path: '/docs' }, { name: doc.title, path: activeHref }]} />
            {visualSlug ? (
              <article className="docs-content">
                <div dangerouslySetInnerHTML={{ __html: leadHtml }} />
                <VisualDiagram slug={visualSlug} />
                {restHtml ? <div dangerouslySetInnerHTML={{ __html: restHtml }} /> : null}
              </article>
            ) : (
              <article className="docs-content" dangerouslySetInnerHTML={{ __html: fullHtml }} />
            )}
          </div>
        </div>
      </section>
    </main>
  );
}
