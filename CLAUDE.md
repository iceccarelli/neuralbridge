# NeuralBridge — durable engineering and product boundaries

Product: **Industrial Autonomous Assurance** (`src/assurance/`) — evidence and
change-assurance for machines whose software can affect safety. `src/neuralbridge/`
is the integration platform it grew out of; adapters are *evolving* unless the
README marks them Supported. `HANDOFF.md` is the current-state document, but
verify it against code and tests — it has been stale before.

## Business boundaries
- NeuralBridge and GridForge / Time-to-Power are independent businesses. Do not
  merge their products, customers, data or infrastructure.
- Zero revenue, zero customers, zero pilots and no production deployment are
  the standing facts until `HANDOFF.md` §4.4 says otherwise with evidence.
  Never write a customer, price validation, market size or valuation claim that
  is not sourced to a named file or document.
- Prices (€390 / €3,900 / €1,290) are unvalidated assertions. Do not create
  Stripe prices, change live pricing, or add SKUs without the founder.

## Engineering invariants
- If it is not enforced in code it is not on the pricing page
  (`billing/plans.py`; `docs/claims-registry.md`).
- `unchecked` / `incomplete` are valid outcomes. Never infer verification from
  missing, mocked or assumed data. Never let an LLM decide a safety conclusion.
- One writer per ledger file (hash chain). Tenant data lives in a per-account
  ledger; the shared ledger is operator-only.
- The offline kit opens no sockets. Awareness, the Art. 14 track and case
  closure are human decisions; software drafts.
- Entitlements are read on every request: 402 when authenticated but unentitled,
  401 with no/invalid key. CLI, API and MCP call the same domain functions.
- Secrets are never logged, printed, committed or pasted into chat.

## Definition of done
```bash
python -m pytest tests/ -q --no-cov     # run with the Postgres env below so nothing skips
ruff check src/ tests/
npx tsc --noEmit && npm run build        # Next.js site
```
Postgres-backed tests (`/ai` control plane) skip honestly without a server:
`NEURALBRIDGE_AI_PG_{HOST,PORT,USER,PASSWORD,TEST_DATABASE}` (see `.github/workflows/ci.yml`).
A green run means **0 skipped**: a skip is a gate that did not run. CI tools are
unpinned unless `requirements/dev.txt` bounds them; run the latest ruff too.
Check the PR's CI before saying it is merged or green — a merge is not a green build.
Use `python -m pytest`, not the bare `pytest` entry point, which may bind a
different interpreter.

## Authority
Do not deploy, rotate or set production secrets, charge customers, send
outreach, or merge to `main` without explicit founder approval. Prepare
checklists instead. The repeatable workflow is in
`.claude/skills/neuralbridge-pmf-execution/SKILL.md`.
