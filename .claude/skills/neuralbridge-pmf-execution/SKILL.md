---
name: neuralbridge-pmf-execution
description: Repeatable session workflow for NeuralBridge product-market-fit execution — verify state, find the next delivery blocker, delegate investigation, ship one bounded slice with tests and independent review, then continue. Use when asked to "continue", "drive NeuralBridge", or work the P0–P4 priorities.
---

# NeuralBridge PMF execution loop

Read `CLAUDE.md` first. Priority order is fixed unless evidence says otherwise:
**P0** launch truth & billing/security → **P1** Continuous Machine Assurance →
**P2** paid-pilot readiness → **P3** integrations on demand → **P4** scale.
Do not start a later priority while an earlier one is broken.

1. **Verify state.** `git status`, `git fetch origin`, current branch vs
   `origin/main`, recent merged PRs. Run the baseline (`python -m pytest tests -q
   --no-cov`, `ruff check src tests`, `npx tsc --noEmit`) before changing
   anything so old failures are not mistaken for regressions. Start Postgres for
   the `/ai` tests if a server binary exists.
2. **Find the next unresolved blocker.** Read the "Remaining" section of
   `HANDOFF.md` and `docs/pmf/PILOT-PROGRAMME.md`; check what real customer
   input (if any) has arrived in `docs/pmf/pilot-ledger.csv`. Customer input
   outranks the roadmap.
3. **Delegate independent investigation** (`.claude/agents/`): one reality
   auditor, one adversarial reviewer. Give each a written objective, scope,
   output and acceptance criteria. Investigations are read-only. Implementation
   agents get disjoint files, ideally in worktrees.
4. **Implement one bounded slice.** State: customer problem, code reused,
   smallest change, tests, limitations, deployment/migration need, rollback.
5. **Prove it.** Full suite + ruff + typecheck/build. Negative and mutation tests
   for guards (temporarily break the guard; the test must fail). No skipping or
   weakening tests to get green.
6. **Independent review** by an agent that did not write the code, given the
   diff, not your conclusion. Fix what it proves; rebut what it cannot.
7. **Integrate.** Lead owns merge, final test results, Git, claims. Update
   `HANDOFF.md` only where state changed. Commit small; push to the session
   branch; open a PR only if asked.
8. **Continue** to the next blocker. Do not end with a plan when a safe,
   testable slice remains.

Never: claim revenue/customers/live readiness without evidence; send outreach;
touch production; relabel a gap as a pass.
