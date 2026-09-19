import fs from 'node:fs';
import path from 'node:path';
import { marked } from 'marked';

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

// Engine pages under docs/assurance/*.md are pure mkdocs snippet-includes of
// deploy/assurance/*.md (see the HTML comment at the top of each — "the real
// content lives at deploy/assurance/X.md, edit it there"). Read the real
// source directly instead of parsing the `--8<--` include directive.
const ENGINE_PAGES: { slug: string; title: string; file: string }[] = [
  { slug: 'collect', title: 'Collect', file: 'COLLECT.md' },
  { slug: 'machine', title: 'Machine safety', file: 'MACHINE.md' },
  { slug: 'machinery', title: 'Machinery Annex III', file: 'MACHINERY.md' },
  { slug: 'fleet', title: 'Fleet advisory', file: 'FLEET.md' },
  { slug: 'watch', title: 'Watch', file: 'WATCH.md' },
  { slug: 'attest', title: 'Attest', file: 'ATTEST.md' },
  { slug: 'kit', title: 'Offline kit', file: 'KIT.md' },
  { slug: 'supplier', title: 'Supplier feeds', file: 'SUPPLIER.md' },
  { slug: 'bridge', title: 'Bridge', file: 'BRIDGE.md' },
  { slug: 'deploy', title: 'Deploying the register', file: 'README.md' },
];

export const DOCS_NAV: { label: string; href: string; children?: { label: string; href: string }[] }[] = [
  { label: 'Home', href: '/docs' },
  { label: 'Getting started', href: '/docs/getting-started' },
  {
    label: 'Assurance engines',
    href: '/docs/assurance',
    children: ENGINE_PAGES.map((p) => ({ label: p.title, href: `/docs/assurance/${p.slug}` })),
  },
  { label: 'Pricing', href: '/docs/pricing' },
  { label: 'Platform status', href: '/docs/platform' },
];

// Rewrite the mkdocs-relative .md links in the source into on-site /docs
// routes so a reader never falls through to a raw GitHub blob mid-article.
const LINK_MAP: Record<string, string> = {
  'getting-started.md': '/docs/getting-started',
  'pricing.md': '/docs/pricing',
  'platform.md': '/docs/platform',
  'assurance/index.md': '/docs/assurance',
  'assurance/deploy.md': '/docs/assurance/deploy',
  ...Object.fromEntries(ENGINE_PAGES.map((p) => [`${p.slug}.md`, `/docs/assurance/${p.slug}`])),
};

function rewriteLinks(markdown: string): string {
  return markdown.replace(/\]\(([a-zA-Z0-9/_-]+\.md)\)/g, (match, target: string) => {
    const mapped = LINK_MAP[target];
    return mapped ? `](${mapped})` : match;
  });
}

function stripFrontmatter(markdown: string): string {
  return markdown.replace(/^---\n[\s\S]*?\n---\n/, '');
}

function firstHeading(markdown: string, fallback: string): string {
  const match = markdown.match(/^#\s+(.+)$/m);
  return match ? match[1].trim() : fallback;
}

export function resolveDocSource(slug: string[] | undefined): { file: string; title: string } | null {
  const parts = slug ?? [];

  if (parts.length === 0) return { file: 'docs/index.md', title: 'Documentation' };
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
    if (engine) return { file: `deploy/assurance/${engine.file}`, title: engine.title };
  }
  return null;
}

export function loadDoc(slug: string[] | undefined): { title: string; html: string; editPath: string } | null {
  const resolved = resolveDocSource(slug);
  if (!resolved) return null;

  const abs = path.join(REPO_ROOT, resolved.file);
  if (!fs.existsSync(abs)) return null;

  const raw = stripFrontmatter(fs.readFileSync(abs, 'utf-8'));
  const title = resolved.title === 'Documentation' ? firstHeading(raw, 'Documentation') : resolved.title;
  const html = marked.parse(rewriteLinks(raw), { async: false }) as string;

  return { title, html, editPath: resolved.file };
}

export function listDocSlugs(): { slug: string[] }[] {
  return [
    { slug: [] },
    { slug: ['getting-started'] },
    { slug: ['pricing'] },
    { slug: ['platform'] },
    { slug: ['assurance'] },
    ...ENGINE_PAGES.map((p) => ({ slug: ['assurance', p.slug] })),
  ];
}
