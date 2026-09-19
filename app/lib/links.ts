export const REPO = 'https://github.com/iceccarelli/neuralbridge';
export const SRC = `${REPO}/tree/main/src/assurance`;
export const DEPLOY_BLOB = `${REPO}/blob/main/deploy/assurance`;
export const SALES = `${REPO}/issues/new?title=Sales+inquiry`;
export const QUICKSTART = `${REPO}#start-here-one-command-inside-your-plant-nothing-uploaded`;
// TEMPORARY: the built MkDocs site (docs/) can't publish to GitHub Pages
// yet — Pages has to be enabled once by a repo admin in Settings before
// GitHub's own API will let CI publish to it (confirmed live; see the
// deploy-docs job comment in .github/workflows/ci.yml). Point at the
// real docs source on GitHub in the meantime so this never 404s; swap
// back to https://iceccarelli.github.io/neuralbridge/ once that Settings
// step is done and the Pages job goes green.
export const DOCS = 'https://github.com/iceccarelli/neuralbridge/blob/main/docs/index.md';
