import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { notFound } from 'next/navigation';
import {
  CATEGORY_SLUG,
  PRODUCT_PAGES,
  SITE_URL,
  capabilityHref,
  getProductPage,
  productHref,
} from '../../lib/productPages';
import { BY_ID, STATUS_LABEL, SURFACE_NAMES } from '../../lib/siteCapabilities';
import { buildMetadata } from '../../lib/seo';
import VisualDiagram from '../../components/VisualDiagram';
import { PRODUCT_VISUAL_BY_SLUG } from '../../lib/visuals';
import '../product.css';

// Every page is generated from app/lib/productPages.ts: the words, the capability ids and the FAQ that
// the FAQPage JSON-LD repeats. tests/test_site_product_pages.py reads the same module and the built HTML.

export function generateStaticParams() {
  return PRODUCT_PAGES.map((p) => ({ slug: p.slug }));
}

type ProductParams = Promise<{ slug: string }>;

export async function generateMetadata({ params }: { params: ProductParams }): Promise<Metadata> {
  const { slug } = await params;
  const page = getProductPage(slug);
  if (!page) return {};
  // The shared helper keeps the canonical, OpenGraph and Twitter tags (and the social image)
  // complete; titles here are already within the limit and unique, so they are used as written.
  return buildMetadata({
    title: page.title,
    absoluteTitle: true,
    description: page.description,
    path: productHref(page.slug),
    ownImage: true,
  });
}

/** A string with `code` spans, as React nodes. */
function inline(text: string): ReactNode[] {
  return text.split('`').map((part, i) => (i % 2 === 1 ? <code key={i}>{part}</code> : part));
}

/** JSON for a script tag: `<` is escaped so no string in the data can close the tag. */
function jsonLd(data: unknown): string {
  return JSON.stringify(data).replace(/</g, '\\u003c');
}

export default async function ProductPage({ params }: { params: ProductParams }) {
  const { slug } = await params;
  const page = getProductPage(slug);
  if (!page) notFound();

  const isCategory = page.slug === CATEGORY_SLUG;
  const crumbs = [
    { name: 'Home', href: '/' },
    { name: 'Product', href: productHref(CATEGORY_SLUG) },
    ...(isCategory ? [] : [{ name: page.name, href: productHref(page.slug) }]),
  ];
  const breadcrumbLd = {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: crumbs.map((c, i) => ({
      '@type': 'ListItem',
      position: i + 1,
      name: c.name,
      item: `${SITE_URL}${c.href}`,
    })),
  };
  // Emitted only because the same questions and answers are printed under "Questions" below.
  const faqLd = {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: page.faq.map((f) => ({
      '@type': 'Question',
      name: f.q,
      acceptedAnswer: { '@type': 'Answer', text: f.a },
    })),
  };

  const related = page.related
    .map((s) => getProductPage(s))
    .filter((p): p is NonNullable<typeof p> => Boolean(p));
  const statusRows = page.statusCaps.map((id) => BY_ID.get(id)).filter((c): c is NonNullable<typeof c> => Boolean(c));

  return (
    <main id="top">
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: jsonLd(breadcrumbLd) }} />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: jsonLd(faqLd) }} />
      <section className="section" style={{ paddingTop: '2.5rem' }}>
        <div className="shell">
          <article className="docs-content product-article">
            <nav className="product-crumbs" aria-label="Breadcrumb">
              <ol>
                {crumbs.map((c, i) => (
                  <li key={c.href + c.name}>
                    {i === crumbs.length - 1 ? <span aria-current="page">{c.name}</span> : <a href={c.href}>{c.name}</a>}
                  </li>
                ))}
              </ol>
            </nav>
            <span className="eyebrow">{page.kicker}</span>
            <h1>{page.h1}</h1>
            <p className="product-definition">{inline(page.definition)}</p>
            {PRODUCT_VISUAL_BY_SLUG[page.slug] ? (
              <VisualDiagram slug={PRODUCT_VISUAL_BY_SLUG[page.slug]} emitJsonLd={false} showCaption={false} />
            ) : null}

            <section id="problem" aria-labelledby="problem-h">
              <h2 id="problem-h">The problem</h2>
              {page.problem.map((p) => (
                <p key={p}>{inline(p)}</p>
              ))}
            </section>

            <section id="how-it-works" aria-labelledby="how-h">
              <h2 id="how-h">How it works here</h2>
              <ol className="product-steps">
                {page.workflow.map((step) => (
                  <li key={step.title}>
                    <strong>{step.title}</strong>
                    {inline(step.body)}
                    {step.caps && step.caps.length > 0 && (
                      <span className="product-step-caps">
                        Capability:{' '}
                        {step.caps.map((id) => (
                          <a key={id} href={capabilityHref(id)}>
                            {id}
                          </a>
                        ))}
                      </span>
                    )}
                  </li>
                ))}
              </ol>
              {isCategory ? (
                <VisualDiagram slug="lifecycle-full-operator-pipeline" emitJsonLd={false} showCaption={false} />
              ) : null}
            </section>

            <section id="what-you-get" aria-labelledby="get-h">
              <h2 id="get-h">What you get</h2>
              {page.youGet.map((p) => (
                <p key={p}>{inline(p)}</p>
              ))}
            </section>

            <section id="not-established" aria-labelledby="not-h">
              <h2 id="not-h">What it does not establish</h2>
              <ul className="product-bullets">
                {page.notEstablished.map((p) => (
                  <li key={p}>{inline(p)}</li>
                ))}
              </ul>
            </section>

            <section id="who-acts" aria-labelledby="who-h">
              <h2 id="who-h">Who acts</h2>
              {page.whoActs.map((p) => (
                <p key={p}>{inline(p)}</p>
              ))}
            </section>

            <section id="status" aria-labelledby="status-h">
              <h2 id="status-h">Status</h2>
              <p>{inline(page.statusNote)}</p>
              <div className="product-table-wrap">
                <table className="product-status">
                  <caption className="product-sr">Status of each capability on the command line, the HTTP API and MCP, read from the capability contract</caption>
                  <thead>
                    <tr>
                      <th scope="col">Capability</th>
                      {SURFACE_NAMES.map((s) => (
                        <th scope="col" key={s}>
                          {s === 'cli' ? 'CLI' : s === 'api' ? 'HTTP API' : 'MCP'}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {statusRows.map((cap) => (
                      <tr key={cap.id}>
                        <th scope="row">
                          <a href={capabilityHref(cap.id)}>{cap.title}</a>
                        </th>
                        {SURFACE_NAMES.map((s) => {
                          const cell = cap.surfaces[s];
                          return (
                            <td key={s}>
                              <span className={`status-${cell.status}`}>{STATUS_LABEL[cell.status]}</span>
                              {cell.names?.map((n) => (
                                <code key={n}>{n}</code>
                              ))}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p>
                Available means the command, route or tool exists in this build. By design means the surface is absent on
                purpose, for the reason given on the <a href="/docs/capabilities">capabilities page</a>. Planned is a known
                gap.
              </p>
            </section>

            <section id="related" aria-labelledby="related-h">
              <h2 id="related-h">Related</h2>
              <ul className="product-related">
                {related.map((r) => (
                  <li key={r.slug}>
                    <a href={productHref(r.slug)}>
                      <strong>{r.name}</strong>
                      <span>{r.intent}</span>
                    </a>
                  </li>
                ))}
              </ul>
              <ul className="product-bullets">
                {page.docs.map((d) => (
                  <li key={d.href}>
                    <a href={d.href}>{d.label}</a>
                  </li>
                ))}
              </ul>
            </section>

            <section id="faq" aria-labelledby="faq-h">
              <h2 id="faq-h">Questions</h2>
              <dl className="product-faq">
                {page.faq.map((f) => (
                  <div key={f.q}>
                    <dt>{f.q}</dt>
                    <dd>{f.a}</dd>
                  </div>
                ))}
              </dl>
            </section>
          </article>
        </div>
      </section>
    </main>
  );
}
