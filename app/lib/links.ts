export const REPO = 'https://github.com/iceccarelli/neuralbridge';
export const SRC = `${REPO}/tree/main/src/assurance`;
export const DEPLOY_BLOB = `${REPO}/blob/main/deploy/assurance`;
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
