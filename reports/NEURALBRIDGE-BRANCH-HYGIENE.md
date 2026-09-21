# NeuralBridge Branch Hygiene Report

Date: 2026-09-21
Verified against: `origin/main` at commit `b732607` (after PR #22 merge), following `git fetch origin --prune`.

## Method

For each candidate stale branch, ran:

```
git merge-base --is-ancestor origin/<branch> origin/main   # exit 0 = pure ancestor of main
git log origin/main..origin/<branch> --oneline             # empty output = no unique commits
```

Both checks were run for real (not assumed) and both agree for all four branches below.

For `gh-pages`, ran `git merge-base origin/main origin/gh-pages`, which exited non-zero (no common ancestor found), confirming an orphan/unrelated history, as expected for a GitHub Pages branch. This branch was **not** subjected to any ancestor/merge test against main — only inspected.

## Findings

| Branch | Role | Verified ancestor-of-main | Recommended action |
|---|---|---|---|
| `main` | Default branch, production history | N/A | **Keep forever** |
| `gh-pages` | Orphan history for GitHub Pages deployment | No common ancestor with main (expected, by design) | **Keep forever** — never merge into main, never delete |
| `claude/awesome-bardeen-6ondvv` | Leftover tip of merged PR #19 | Yes (0 unique commits vs main) | Safe to delete |
| `claude/neuralbridge-ai-phase1` | Leftover tip of merged PR #20 | Yes (0 unique commits vs main) | Safe to delete |
| `claude/neuralbridge-ai-phase2` | Leftover tip of merged PR #21 | Yes (0 unique commits vs main) | Safe to delete |
| `claude/beautiful-hypatia-pqritw` | Leftover tip of merged PR #22 | Yes (0 unique commits vs main) | Safe to delete |

All four `claude/*` branches are pure ancestors of `origin/main` — their content is fully merged in, and `git log origin/main..origin/<branch>` returned no commits for any of them. Deleting them removes no history; it only removes stale refs.

## Deletion commands for the founder

These branches cannot be deleted from this agent environment (see "Agent limitation" below). The founder should run one of the following.

### Option A — GitHub UI
1. Go to the repo's Pull Requests tab, open each of PR #19, #20, #21, #22 (already merged).
2. On each merged PR page, click the "Delete branch" button that GitHub shows next to the merge confirmation.
   - If that button is no longer visible, go to **Code → branches** (`https://github.com/iceccarelli/neuralbridge/branches`), find each branch below, and click the trash-can/delete icon next to it.

Branches to delete via UI:
- `claude/awesome-bardeen-6ondvv`
- `claude/neuralbridge-ai-phase1`
- `claude/neuralbridge-ai-phase2`
- `claude/beautiful-hypatia-pqritw`

### Option B — `gh` CLI

```
gh api -X DELETE repos/iceccarelli/neuralbridge/git/refs/heads/claude/awesome-bardeen-6ondvv
gh api -X DELETE repos/iceccarelli/neuralbridge/git/refs/heads/claude/neuralbridge-ai-phase1
gh api -X DELETE repos/iceccarelli/neuralbridge/git/refs/heads/claude/neuralbridge-ai-phase2
gh api -X DELETE repos/iceccarelli/neuralbridge/git/refs/heads/claude/beautiful-hypatia-pqritw
```

Equivalently, with plain git and appropriate push credentials:

```
git push origin --delete claude/awesome-bardeen-6ondvv
git push origin --delete claude/neuralbridge-ai-phase1
git push origin --delete claude/neuralbridge-ai-phase2
git push origin --delete claude/beautiful-hypatia-pqritw
```

## Hard rules

- **Keep `main` and `gh-pages` forever.** Never delete either.
- **Never merge `gh-pages` into `main`** (or vice versa) — they are unrelated, orphaned histories by design (Pages content vs. application source).
- **Never force-push** to `main` or `gh-pages`.

## Agent limitation (this session)

This agent attempted a single non-destructive test — `git push origin --delete claude/awesome-bardeen-6ondvv` — solely to confirm whether this environment has permission to delete remote branches. The push was **rejected with HTTP 403** (`RPC failed; HTTP 403`), and the branch was **not deleted** (confirmed still present on the remote). No retry, force-push, or alternate-auth workaround was attempted, per instructions. The founder must run the deletion commands above from an environment/account with push-delete rights on the repo.
