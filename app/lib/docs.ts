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
  'assurance/deploy.md': '/docs/assurance/deploy',
  'ROADMAP.md': '/roadmap',
  'SECURITY.md': '/security',
  ...Object.fromEntries(ENGINE_PAGES.map((p) => [`${p.slug}.md`, `/docs/assurance/${p.slug}`])),
};

// README.md#some-anchor is a root-relative link only ROADMAP.md uses today,
// pointing at the platform section — the on-site equivalent is the
// homepage's own platform section.
const FRAGMENT_LINK_MAP: Record<string, string> = {
  'README.md#neuralbridge--the-platform-underneath': '/#platform',
};

function rewriteLinks(markdown: string): string {
  return markdown
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

/**
 * The first plain-prose paragraph of a markdown document, as one line of text for a meta
 * description: headings, HTML comments, fenced code, tables, lists, block quotes and include
 * directives are skipped; links, code and emphasis are reduced to their words; the result is cut
 * at a word boundary at or before 200 characters. Empty string when the document has no prose.
 */
export function firstParagraph(markdown: string): string {
  const body = markdown.replace(/<!--[\s\S]*?-->/g, '').replace(/^(```|~~~)[\s\S]*?^\1/gm, '');
  for (const block of body.split(/\n\s*\n/)) {
    const text = block.trim();
    if (!text || /^(#|\||>|[-*+] |\d+\. |!!!|--8<--|<|---)/.test(text)) continue;
    const plain = text
      .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
      .replace(/`/g, '')
      // Emphasis markers come off only where they open or close a span: snake_case and 2*3 keep theirs.
      .replace(/(\*\*|__)(\S(?:.*?\S)?)\1/g, '$2')
      .replace(/(^|[\s(])([*_])(\S(?:.*?\S)?)\2(?=$|[\s).,;:!?])/g, '$1$3')
      .replace(/\s+/g, ' ')
      .trim();
    if (plain.length < 20) continue;
    if (plain.length <= 200) return plain;
    const cut = plain.slice(0, 200);
    return `${cut.slice(0, Math.max(cut.lastIndexOf(' '), 1)).replace(/[,;:]$/, '')}…`;
  }
  return '';
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
  const title = resolved.title === 'Documentation' ? firstHeading(raw, 'Documentation') : resolved.title;
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
