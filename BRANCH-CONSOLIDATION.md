# Branch consolidation report — 2026-09-19

Full audit of every remote head in `iceccarelli/neuralbridge`, run against
`main` at `8f77db9` (Stage H1, #14). Goal: prove no branch holds content that
isn't already on `main`, then remove the obsolete ones. Result: **zero unique
content found on any of the 12 `claude/*` branches** — all of it was already
captured by squash-merged PRs. Branch *deletion* itself is blocked by this
session's tooling (details in Phase 3 below) and needs to be finished by a
human or a session with delete rights.

## Method

Squash-merging a PR creates a brand-new commit SHA on `main`, so the source
branch's tip stays "ahead" of `main` forever even after 100% of its diff has
landed — that's a cosmetic artifact, not lost work. Naive ahead/behind counts
or `git diff --stat` alone cannot tell the two cases apart. So each branch was
checked two ways:

1. **SHA proof**: the branch's current tip SHA (from `git ls-remote`) was
   matched against the `head.sha` GitHub recorded on the PR that merged it.
   An exact match plus a `MERGED` PR state proves nothing was pushed to the
   branch after its content was captured.
2. **Content spot-check**: for the branches with the largest ahead-counts,
   representative files were byte-compared (`git show <ref>:<path> | md5sum`)
   between the branch tip and `origin/main`.

## Phase 0 — Inventory

| Branch | Ahead/Behind vs main | Tree vs main | Merged via | Classification |
|---|---|---|---|---|
| `claude/great-fermat-gr9inv` | 13 / 2 | differs | #3 | `CONTENT_ALREADY_ON_MAIN` |
| `claude/stage-a-aws-parity` | ahead | differs | #4 | `CONTENT_ALREADY_ON_MAIN` |
| `claude/stage-b-money-wiring` | ahead | differs | #5 | `CONTENT_ALREADY_ON_MAIN` |
| `claude/stage-c-niche-dominance` | ahead | differs | #6 | `CONTENT_ALREADY_ON_MAIN` |
| `claude/purge-fake-docs` | ahead | differs | #7 | `CONTENT_ALREADY_ON_MAIN` |
| `claude/docs-404-and-honesty` | ahead | differs | #8 | `CONTENT_ALREADY_ON_MAIN` |
| `claude/pages-enablement` | ahead | differs | #9 | `CONTENT_ALREADY_ON_MAIN` |
| `claude/stage-d-alive-seo` | ahead | differs | #10 | `CONTENT_ALREADY_ON_MAIN` |
| `claude/stage-f-design-system` | ahead | differs | #11 | `CONTENT_ALREADY_ON_MAIN` |
| `claude/stage-g1-openapi-developers` | ahead | differs | #12 | `CONTENT_ALREADY_ON_MAIN` |
| `claude/stage-f4-og-agent-manifest` | ahead | differs | #13 | `CONTENT_ALREADY_ON_MAIN` |
| `claude/stage-h1-dual-illustrations` | ahead | differs | #14 | `CONTENT_ALREADY_ON_MAIN` |
| `gh-pages` | n/a — unrelated history | differs | never merged | `DO_NOT_MERGE` (Pages artifact branch) |

"Tree differs" is expected and correct for every `claude/*` branch: `main`
has continued evolving in every later stage after each branch's PR merged
(e.g. `app/page.tsx` was rewritten across ~6 subsequent stages). It does not
indicate lost content — see Phase 1.

Open PRs at time of audit: **zero.**

## Phase 1 — Salvage

Spot-checked files, chosen from the branches with the largest diffstats
(highest apparent risk):

- `app/components/RotatingImage.tsx` (`stage-h1`) — byte-identical to main.
- `public/openapi.json` (`stage-g1-openapi-developers`) — byte-identical to main.
- `app/DESIGN.md` (`stage-f-design-system`) — differs, but main's version is a
  strict superset (everything from the branch, plus a later "## Imagery"
  section added by Stage H1). Nothing removed.
- `tests/support.py`, `.github/workflows/assurance.yml`,
  `tests/test_assurance_collect.py` (`great-fermat-gr9inv`, the branch with
  the most ahead-commits) — byte-identical to main.
- `app/page.tsx` (`great-fermat-gr9inv`) — differs, expected: rewritten in
  every subsequent stage (B, C, D, F, G1, H1).

**Finding: zero unique/left-behind files on any of the 12 `claude/*`
branches.** Per the task's own instruction to skip inventing salvage commits
when none is needed, no salvage branch or PR was created.

## Phase 2 — Integration check

All required paths confirmed present on `origin/main` (`8f77db9`):

- `app/components/RotatingImage.tsx`, `public/images/variants/a`,
  `public/images/variants/b`
- `app/developers/page.tsx`, `public/openapi.json`,
  `scripts/export_openapi.py`
- `app/DESIGN.md`, `SMOKE.md`, `ROADMAP.md`
- `app/solutions/[slug]/page.tsx`, `app/lib/solutions.ts` (buyer pages)
- `src/assurance/billing/plans.py`, `src/assurance/api/service.py`
  (CORS middleware confirmed wired, 2 occurrences)
- `public/.well-known/agent.json`, `app/opengraph-image.tsx`

Verified healthy on `main`'s current HEAD:

- `pytest tests/ -q` → 747 passed
- `npm run build` → clean
- GitHub Actions on commit `8f77db9` → both most recent runs `success`

`gh-pages` was **not** merged into `main` (forbidden by design — it's a
historical MkDocs build-artifact branch from the `mkdocs gh-deploy` era, not
application source). If the docs site still 404s, that's Pages
source/enablement configuration in repo Settings, not something this task
fixes by merging artifact history into app source.

## Phase 3 — Deletion: BLOCKED, needs human action

All 12 `claude/*` branches are safe to delete — content 100% captured, proven
above. Deletion was attempted and failed at every layer available in this
session:

- `git push origin --delete <branch>` → `HTTP 403` for all 12 (git-protocol
  level; ordinary pushes/branch creation work fine, so this is a delete-only
  restriction on this session's credentials).
- No GitHub MCP tool exists in this session's toolset for branch deletion or
  arbitrary REST calls (confirmed by search — no `delete_branch`, no generic
  API-call tool).

**Refs that need delete rights granted (or to be deleted directly) by
someone with permission:**

```
claude/great-fermat-gr9inv
claude/stage-a-aws-parity
claude/stage-b-money-wiring
claude/stage-c-niche-dominance
claude/purge-fake-docs
claude/docs-404-and-honesty
claude/pages-enablement
claude/stage-d-alive-seo
claude/stage-f-design-system
claude/stage-g1-openapi-developers
claude/stage-f4-og-agent-manifest
claude/stage-h1-dual-illustrations
```

`main` and `gh-pages` must **not** be deleted. Whether `gh-pages` can
eventually be removed depends on whether GitHub Pages → Settings → Source is
still set to "Deploy from a branch (gh-pages)" or has been switched to the
Actions-based flow (`actions/deploy-pages`) introduced in earlier stages —
that setting isn't readable from this session, so it's kept conservatively
for now. Recommend checking Settings → Pages before deleting it.

## Phase 4 — Before / after

- **Before**: 14 remote heads (`main`, `gh-pages`, 12 `claude/*`).
- **After (this session)**: still 14 — Phase 3 deletion is blocked, see
  above. Once the 12 refs above are deleted by someone with rights, the
  target end state is `main` (+ `gh-pages`, pending the Settings check).
- **No valuable commit was left only on a branch tip.** Every commit unique
  to a `claude/*` branch's history predates its squash-merge and is fully
  represented in the resulting merge commit on `main`; nothing on any tip
  postdates its PR merge.
