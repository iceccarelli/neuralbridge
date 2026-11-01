import fs from 'node:fs';
import path from 'node:path';
import { marked } from 'marked';
import { firstParagraph } from './docDescription';
import { REPO_PUBLIC, stripRepoLinks } from './links';

export { firstParagraph };

// The on-site /docs section renders the same markdown that ships in this
// repository's docs/ (and, for the engine pages, deploy/assurance/ — mkdocs
// snippet-includes those, so we read the same source of truth directly)
// so buyers reading neuralbridge.io never land on a github.io 404 or a raw
// GitHub blob. This is not a copy: it is the same files, read at build time.

const REPO_ROOT = path.join(process.cwd());

export interface DocPage {
  slug: string[];
  title: string;
  sourcePath: string;
}

// Engine pages under docs/assurance/*.md are pure mkdocs snippet-includes of the real guide (see
// the HTML comment at the top of each: "the real content lives at ..., edit it there"). Read the
// real source directly instead of parsing the `--8<--` include directive. `source` is relative to
// the repository root; a page whose source is absent is neither listed nor routed (listDocSlugs),
// and tests/test_site_capabilities_contract.py fails if one is declared here.
const ENGINE_PAGES: { slug: string; title: string; source: string }[] = [
  { slug: 'collect', title: 'Collect', source: 'deploy/assurance/COLLECT.md' },
  { slug: 'machine', title: 'Machine safety', source: 'deploy/assurance/MACHINE.md' },
  { slug: 'machinery', title: 'Machinery Annex III', source: 'deploy/assurance/MACHINERY.md' },
  { slug: 'fleet', title: 'Fleet advisory', source: 'deploy/assurance/FLEET.md' },
  { slug: 'change', title: 'Change assurance', source: 'deploy/assurance/CHANGE.md' },
  { slug: 'intel', title: 'Public-source intelligence', source: 'deploy/assurance/INTEL.md' },
  { slug: 'watch', title: 'Watch', source: 'deploy/assurance/WATCH.md' },
  { slug: 'attest', title: 'Attest', source: 'deploy/assurance/ATTEST.md' },
  { slug: 'key-ceremony', title: 'Key ceremony', source: 'deploy/assurance/KEY-CEREMONY.md' },
  { slug: 'trust-runbook', title: 'Trust runbook', source: 'deploy/assurance/TRUST-RUNBOOK.md' },
  { slug: 'kit', title: 'Offline kit', source: 'deploy/assurance/KIT.md' },
  { slug: 'supplier', title: 'Supplier feeds', source: 'deploy/assurance/SUPPLIER.md' },
  { slug: 'bridge', title: 'Bridge', source: 'deploy/assurance/BRIDGE.md' },
  { slug: 'pipeline', title: 'Operator pipeline', source: 'deploy/assurance/PIPELINE.md' },
  // deploy/assurance/README.md was deleted; the deploy walkthrough that exists is DEPLOY_NOW.md.
  { slug: 'deploy', title: 'Deploying (rehearse in test mode first)', source: 'DEPLOY_NOW.md' },
];

export const DOCS_NAV: { label: string; href: string; children?: { label: string; href: string }[] }[] = [
  { label: 'Home', href: '/docs' },
  { label: 'Getting started', href: '/docs/getting-started' },
  {
    label: 'Assurance engines',
    href: '/docs/assurance',
    children: ENGINE_PAGES.map((p) => ({ label: p.title, href: `/docs/assurance/${p.slug}` })),
  },
  { label: 'Capabilities', href: '/docs/capabilities' },
  { label: 'Pricing', href: '/docs/pricing' },
  { label: 'Platform status', href: '/docs/platform' },
];

// Rewrite the mkdocs-relative .md links (and root-doc-relative ones, for
// ROADMAP.md/SECURITY.md) into on-site routes so a reader never falls
// through to a raw GitHub blob mid-article.
const LINK_MAP: Record<string, string> = {
  'getting-started.md': '/docs/getting-started',
  'pricing.md': '/docs/pricing',
  'platform.md': '/docs/platform',
  'docs/platform.md': '/docs/platform',
  'docs/index.md': '/docs',
  'assurance/index.md': '/docs/assurance',
  'ROADMAP.md': '/roadmap',
  'SECURITY.md': '/security',
  // A guide is linked by its mkdocs name (`watch.md`) or by its own file name (`KEY-CEREMONY.md`).
  ...Object.fromEntries(ENGINE_PAGES.map((p) => [`${p.slug}.md`, `/docs/assurance/${p.slug}`])),
  ...Object.fromEntries(ENGINE_PAGES.map((p) => [`assurance/${p.slug}.md`, `/docs/assurance/${p.slug}`])),
  ...Object.fromEntries(ENGINE_PAGES.map((p) => [p.source.split('/').pop() as string, `/docs/assurance/${p.slug}`])),
};

// README.md#some-anchor is a root-relative link only ROADMAP.md uses today,
// pointing at the platform section — the on-site equivalent is the
// homepage's own platform section.
const FRAGMENT_LINK_MAP: Record<string, string> = {
  'README.md#neuralbridge--the-platform-underneath': '/#platform',
};

export function rewriteLinks(markdown: string): string {
  // With the repository private (lib/links.ts REPO_PUBLIC false) a link into it would 404 for a
  // reader: keep the anchor text, drop the href.
  return (REPO_PUBLIC ? markdown : stripRepoLinks(markdown))
    .replace(/\]\(([a-zA-Z0-9/_-]+\.md#[a-zA-Z0-9-]+)\)/g, (match, target: string) => {
      const mapped = FRAGMENT_LINK_MAP[target];
      return mapped ? `](${mapped})` : match;
    })
    .replace(/\]\(([a-zA-Z0-9/_-]+\.md)\)/g, (match, target: string) => {
      const mapped = LINK_MAP[target];
      return mapped ? `](${mapped})` : match;
    });
}

function stripFrontmatter(markdown: string): string {
  return markdown.replace(/^---\n[\s\S]*?\n---\n/, '');
}

export function resolveDocSource(slug: string[] | undefined): { file: string; title: string } | null {
  const parts = slug ?? [];

  // /docs itself (no slug) has no markdown source: docs/index.md was removed, and app/docs renders
  // the landing from DOCS_NAV.
  if (parts.length === 1 && parts[0] === 'getting-started') {
    return { file: 'docs/getting-started.md', title: 'Getting started' };
  }
  if (parts.length === 1 && parts[0] === 'pricing') return { file: 'docs/pricing.md', title: 'Pricing' };
  if (parts.length === 1 && parts[0] === 'platform') return { file: 'docs/platform.md', title: 'Platform status' };
  if (parts.length === 1 && parts[0] === 'assurance') {
    return { file: 'docs/assurance/index.md', title: 'Assurance engines' };
  }
  if (parts.length === 2 && parts[0] === 'assurance') {
    const engine = ENGINE_PAGES.find((p) => p.slug === parts[1]);
    if (engine) return { file: engine.source, title: engine.title };
  }
  return null;
}


/**
 * A page has one h1. Some engine guides concatenate several documents (WATCH.md has five `# `
 * headings), so every h1 after the first is rendered as an h2 instead of a second page title.
 */
export function singleH1(html: string): string {
  let opens = 0;
  let closes = 0;
  return html.replace(/<(\/?)h1\b/g, (match, slash: string) => {
    if (slash) return ++closes === 1 ? match : '</h2';
    return ++opens === 1 ? match : '<h2';
  });
}

export function loadDoc(slug: string[] | undefined): { title: string; html: string; editPath: string; description: string } | null {
  const resolved = resolveDocSource(slug);
  if (!resolved) return null;

  const abs = path.join(/*turbopackIgnore: true*/ REPO_ROOT, resolved.file);
  if (!fs.existsSync(abs)) return null;

  const raw = stripFrontmatter(fs.readFileSync(abs, 'utf-8'));
  const title = resolved.title;
  const html = singleH1(marked.parse(rewriteLinks(raw), { async: false }) as string);

  return { title, html, editPath: resolved.file, description: firstParagraph(raw) };
}

// Root-level meta docs (ROADMAP.md, SECURITY.md) ported on-site the same
// way — same source of truth, read at build time, not a copy that can
// drift. These aren't part of the /docs tree (no sidebar), just rendered
// standalone with the same markdown pipeline.
export function loadRootDoc(file: string, title: string): { title: string; html: string; editPath: string } | null {
  const abs = path.join(/*turbopackIgnore: true*/ REPO_ROOT, file);
  if (!fs.existsSync(abs)) return null;

  const raw = stripFrontmatter(fs.readFileSync(abs, 'utf-8'));
  const html = singleH1(marked.parse(rewriteLinks(raw), { async: false }) as string);

  return { title, html, editPath: file };
}

/**
 * Every docs page that can be rendered. A page whose source file is absent is not listed, so
 * the static params and the sitemap never advertise a URL that would answer not-found.
 */
export function listDocSlugs(): { slug: string[] }[] {
  const all = [
    { slug: ['getting-started'] },
    { slug: ['pricing'] },
    { slug: ['platform'] },
    { slug: ['assurance'] },
    ...ENGINE_PAGES.map((p) => ({ slug: ['assurance', p.slug] })),
  ];
  return all.filter(({ slug }) => {
    const resolved = resolveDocSource(slug.length ? slug : undefined);
    return resolved !== null && fs.existsSync(path.join(/*turbopackIgnore: true*/ REPO_ROOT, resolved.file));
  });
}
