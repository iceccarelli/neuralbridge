import Link from 'next/link';
import { DOCS_NAV } from '../lib/docs';
import { REPO } from '../lib/links';

/** The docs navigation, shared by the markdown pages and the generated capabilities page. */
export default function DocsSidebar({ activeHref, editPath }: { activeHref: string; editPath: string }) {
  return (
    <nav className="docs-sidebar" aria-label="Documentation">
      {DOCS_NAV.map((item) => (
        <div key={item.href} className="docs-nav-group">
          <Link href={item.href} className={`docs-nav-link ${activeHref === item.href ? 'active' : ''}`}>
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
      <a className="docs-nav-link docs-nav-edit" href={`${REPO}/blob/main/${editPath}`} target="_blank" rel="noreferrer">
        Edit this page on GitHub ↗
      </a>
    </nav>
  );
}
