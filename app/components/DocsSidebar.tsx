import Link from 'next/link';
import { DOCS_NAV } from '../lib/docs';
import RepoLink from './RepoLink';

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
      <RepoLink path={`/blob/main/${editPath}`} className="docs-nav-link docs-nav-edit">
        Edit this page on GitHub ↗
      </RepoLink>
    </nav>
  );
}
