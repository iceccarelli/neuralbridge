import Link from 'next/link';
import { breadcrumbJsonLd, jsonLdString, type Crumb } from '../lib/seo';

/** A visible breadcrumb trail and the BreadcrumbList that describes exactly the same trail. The last crumb is the current page. */
export default function Breadcrumbs({ trail }: { trail: Crumb[] }) {
  return (
    <>
      <nav className="docs-breadcrumb" aria-label="Breadcrumb">
        <ol>
          {trail.map((crumb, i) => (
            <li key={crumb.path}>
              {i < trail.length - 1 ? (
                <Link href={crumb.path} prefetch={false}>{crumb.name}</Link>
              ) : (
                <span aria-current="page">{crumb.name}</span>
              )}
            </li>
          ))}
        </ol>
      </nav>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: jsonLdString(breadcrumbJsonLd(trail)) }} />
    </>
  );
}
