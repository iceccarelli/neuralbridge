// The one switch for every link into the source repository. The repository is private and the
// code is proprietary (see LICENSE), so by default the site links to no source tree, issue tracker,
// blob or profile: anything other than the exact string 'true' is false. Flip it only for a public
// release or a separate public docs repository. NEXT_PUBLIC_* is inlined at build time, so this is
// a build-time decision; public/llms.txt and public/.well-known/agent.json follow the same flag via
// scripts/export_site_static.py.
export const REPO_PUBLIC = process.env.NEXT_PUBLIC_REPO_PUBLIC === 'true';

// The only place the repository and profile URLs are spelled. tests/test_site_repo_links.py fails
// if they appear anywhere else under app/ or in the static files. The flag is tested inline, on the
// expression that holds each URL, so that with the flag off the bundler drops the URL from the build
// output altogether instead of shipping it as an unused constant.

/** A URL inside the repository (`path` is a suffix such as '#readme' or '' for the root), or null when the repo is not public. */
export function repoLink(path = ''): string | null {
  return process.env.NEXT_PUBLIC_REPO_PUBLIC === 'true' ? `https://github.com/iceccarelli/neuralbridge${path}` : null;
}

/** The repository owner's profile, or null when the repo is not public. */
export function ownerLink(): string | null {
  return process.env.NEXT_PUBLIC_REPO_PUBLIC === 'true' ? 'https://github.com/iceccarelli' : null;
}

/** A path under src/assurance in the repository, or null. */
export function srcLink(sub = ''): string | null {
  return repoLink(`/tree/main/src/assurance${sub}`);
}

/** A file under deploy/assurance in the repository, or null. */
export function deployBlobLink(file: string): string | null {
  return repoLink(`/blob/main/deploy/assurance/${file}`);
}

/** JSON-LD sameAs entries for the repository: [] when the repo is not public. */
export function repoSameAs(): string[] {
  const l = repoLink();
  return l ? [l] : [];
}

// On-site /contact (app/contact/page.tsx) replaces the bare GitHub issue —
// buyers get a real form, not a repo dump. Supplier and Register/Cell sales
// both route here; the intent query param pre-selects the right topic.
export const SALES = '/contact';
export const SALES_SUPPLIER = '/contact?intent=supplier';
export const QUICKSTART = '/docs/getting-started';
// On-site /docs (app/docs/[[...slug]]/page.tsx) renders the same markdown
// that ships in docs/ and deploy/assurance/ — buyers never leave
// neuralbridge.io or hit a github.io 404. GitHub Pages (mkdocs, built from
// the same docs/ tree) is the optional mirror once a repo admin enables
// Pages in Settings and the deploy-docs job goes green; flip this back to
// https://iceccarelli.github.io/neuralbridge/ at that point if a static
// mirror is still wanted. Until then, on-site wins.
export const DOCS = '/docs';

const REPO_URL_RE = /https:\/\/github\.com\/iceccarelli(?:\/neuralbridge)?[^\s)\]"'<>]*/;

/**
 * Markdown with every link into the repository made plain text: `[text](repo-url)` keeps `text` and
 * drops the href, and a clone-command line becomes a comment saying to get the source from us. Used
 * by lib/docs.ts when REPO_PUBLIC is false.
 */
export function stripRepoLinks(markdown: string): string {
  const link = new RegExp(`\\[([^\\]]*)\\]\\(${REPO_URL_RE.source}\\)`, 'g');
  const clone = new RegExp(`^([ \\t]*)git clone ${REPO_URL_RE.source}[ \\t]*$`, 'gm');
  return markdown
    .replace(link, '$1')
    .replace(clone, '$1# get a copy of the source from NeuralBridge (see the Contact page)');
}
