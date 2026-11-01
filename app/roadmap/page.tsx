import type { Metadata } from 'next';
import { REPO } from '../lib/links';
import { loadRootDoc } from '../lib/docs';
import {
  CAPABILITIES,
  COUNTS,
  SERVICE_TITLE,
  SURFACE_NAMES,
  type Capability,
  type SurfaceName,
} from '../lib/siteCapabilities';

export const metadata: Metadata = {
  title: 'Roadmap | Industrial Autonomous Assurance',
  description: 'What is planned and not yet built, read from the capability catalogue in the code — nothing is marked done unless it is gated in code and covered by tests.',
  alternates: { canonical: '/roadmap' },
  openGraph: {
    title: 'Roadmap | Industrial Autonomous Assurance',
    description: 'Planned gaps, each with the reason the catalogue records for it.',
    url: '/roadmap',
    type: 'website',
  },
};

const SURFACE_HEADING: Record<SurfaceName, string> = { cli: 'CLI', api: 'HTTP API', mcp: 'MCP' };

interface PlannedItem {
  cap: Capability;
  surface: SurfaceName;
  reason: string;
}

// The planned list is derived, not written: a capability appears here only when the catalogue
// in src/assurance/capabilities.py declares one of its surfaces `planned`.
function plannedItems(): PlannedItem[] {
  const out: PlannedItem[] = [];
  for (const cap of CAPABILITIES) {
    for (const surface of SURFACE_NAMES) {
      const cell = cap.surfaces[surface];
      if (cell.status === 'planned') out.push({ cap, surface, reason: cell.reason ?? '' });
    }
  }
  return out;
}

export default function RoadmapPage() {
  // A hand-written ROADMAP.md wins when the repository has one.
  const doc = loadRootDoc('ROADMAP.md', 'Roadmap');
  if (doc) {
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

  const planned = plannedItems();
  const byService = new Map<string, PlannedItem[]>();
  for (const item of planned) {
    const list = byService.get(item.cap.service) ?? [];
    list.push(item);
    byService.set(item.cap.service, list);
  }

  return (
    <main id="top">
      <section className="section" style={{ paddingTop: '3rem' }}>
        <div className="shell docs-standalone">
          <article className="docs-content">
            <h1>Roadmap</h1>
            <p>
              This page is generated from the capability catalogue in the code, not written by
              hand. It lists the places where the catalogue says a command, route or tool is{' '}
              <strong>planned</strong>: it does not exist in this build. It gives no dates and no
              promises.
            </p>
            <p>
              Of {COUNTS.capabilities} catalogued capabilities, {planned.length} surface
              {planned.length === 1 ? ' is' : 's are'} marked planned. Surfaces marked{' '}
              <em>by design</em> are not on this list: they are left off on purpose, usually because the
              act is a named person’s decision. The full matrix is on{' '}
              <a href="/docs/capabilities">Capabilities by surface</a>.
            </p>
            {planned.length === 0 ? (
              <p>The catalogue currently declares nothing as planned.</p>
            ) : (
              [...byService.entries()].map(([service, items]) => (
                <section key={service}>
                  <h2>{SERVICE_TITLE[service] ?? service}</h2>
                  <ul>
                    {items.map(({ cap, surface, reason }) => (
                      <li key={`${cap.id}:${surface}`}>
                        <strong>{cap.title}</strong> — {SURFACE_HEADING[surface]} <code>{cap.id}</code>
                        {reason ? <>: {reason}</> : null}
                      </li>
                    ))}
                  </ul>
                </section>
              ))
            )}
          </article>
        </div>
      </section>
    </main>
  );
}
