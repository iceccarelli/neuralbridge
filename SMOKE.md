# Smoke test — run from a browser after every deploy

Five checks, done from a real browser (not curl — the point is to prove the
browser-side CORS and JS wiring actually works, which curl cannot tell you).
Run these before telling anyone the site is live, and again after any change
to the API, Stripe config, or `NEXT_PUBLIC_ASSURANCE_API_URL`.

1. **Live plans.** Visit `https://neuralbridge.io/#pricing`. The pricing
   cards must show the green "Live from GET /v1/plans" note, not silently
   sit on the static fallback.
2. **Buy appears.** On Register or Cell, the button must read **Buy**, not
   "Talk to sales" — that only happens once `purchasable` comes back true
   from the live API.
3. **Playground Validate.** On the homepage, submit the free Validator
   playground. It must return a real response (missing-field issues), not
   the "not deployed yet" message.
4. **Checkout success path.** Click Buy, enter a real email, and pay with a
   Stripe test card (`4242 4242 4242 4242`, any future expiry, any CVC) if
   using the sandbox Stripe account, or a real card if live. You should land
   on `https://neuralbridge.io/checkout/success` and see a one-time API key
   within a few seconds.
5. **CORS.** Run the check from `deploy/assurance/README.md`:
   ```bash
   curl -i -X OPTIONS https://<your-fly-app>.fly.dev/v1/plans \
        -H 'Origin: https://neuralbridge.io' -H 'Access-Control-Request-Method: GET' \
        | grep -i access-control-allow-origin
   ```
   Must echo `https://neuralbridge.io`.

If all five pass, the product takes real money. If any fails, do not
announce the site as live — fix the matching step in `DEPLOY_NOW.md` first.

None of this needs a code change — every value it depends on is a
`REPLACE_*` placeholder or an example host in `.env.example`. Fill those in
with real Fly/Stripe values and redeploy; nothing else moves.
