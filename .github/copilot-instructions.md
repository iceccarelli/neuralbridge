# Instructions for GitHub Copilot (code review, coding agent, chat)

Read `CLAUDE.md` first; it is authoritative and these lines only restate it.

- Product: Industrial Autonomous Assurance (`src/assurance/`). `src/neuralbridge/` is the older
  integration platform; its adapters are evolving unless the README marks them Supported.
- Verify any prose against the code and its tests, `src/assurance/capabilities.py`
  (`python -m assurance capabilities --check`), `docs/claims-registry.md` and `docs/GO-LIVE.md`.
- If it is not enforced in code it is not on the pricing page (`billing/plans.py`).
  Never invent a customer, pilot, price validation, market size or valuation: that needs a
  named, dated source and `docs/pmf/pilot-ledger.csv`.
- `unchecked` / `incomplete` are valid outcomes. Never infer verification from missing, mocked
  or assumed data. Never let an LLM decide a safety conclusion.
- One writer per ledger file. Tenant data lives in a per-account ledger; the shared ledger is
  operator-only. Entitlements are read on every request: 402 authenticated but unentitled,
  401 no or invalid key. CLI, API and MCP call the same domain functions.
- The offline kit opens no sockets. Awareness, the Art. 14 track and case closure are human
  decisions; software drafts.
- Secrets are never logged, printed or committed.
- Do not deploy, change prices or Stripe objects, send outreach, or merge to `main`: those are
  the founder's. Open a PR instead.
- Definition of done: `python -m pytest tests/ -q --no-cov` with the Postgres env set (0 skipped),
  `ruff check src/ tests/`, `npx tsc --noEmit && npm run build`.
- When reviewing, flag in particular: entitlement or tenant-isolation bypass, a public claim
  without enforcement, anonymous routes that disclose configuration, and any skipped or
  loosened test.
