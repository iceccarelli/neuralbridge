# Smoke test — after every staging deploy

**Status.** Nothing has been deployed, and neither part below has been run against
a hosted host. Part A is automated and has been proven only against local servers
(`tests/test_staging_rehearsal.py`). Part B is the five browser checks, which only
you can do. Both are Stripe **test mode** only; none needs, or should be given, a
live key or a real card.

## Part A — automated, one command

```bash
export REHEARSAL_BASE_URL=https://<your-staging-app>.fly.dev
export REHEARSAL_REGISTER_KEY=...        # optional: a Register-only TEST key, for the 402 check
python scripts/staging_rehearsal.py smoke --expect-purchasable register,cell
```

It never writes anything on the host and never calls Stripe, but it is not read-only in the
sense of "GETs only". Every kind of request it sends, to the host you gave and no other (no
proxy from the environment, no redirects followed):

- `GET /healthz`, `GET /v1/plans`;
- `POST /v1/machine/verify` with the body `{}` three times, expecting `401` with no key, `401`
  with a made-up key and `402` with your Register key (an authenticated caller without the
  entitlement, so the route refuses before it reads the body and nothing is recorded; only the
  third carries a credential, and only to this host); if that key is *admitted* it also sends
  `GET /v1/me` to say what plan the key is on;
- two `OPTIONS /v1/plans` CORS preflights (the marketing origin, and a hostile one);
- a TLS handshake to read the certificate (a raw socket: no HTTP, and no proxy);
- for an https host on the default port, **one** plain-http request to port 80:
  `GET http://<host>/healthz` with no credentials of any kind, only to see that it redirects to
  https on the same host.

It prints `PASS` / `FAIL` / `UNCHECKED` per step: `/healthz` (stores open, `auth_mode`
is `api_key`, never `open`), `/v1/plans` equal to `billing/plans.py` apart from
`purchasable`, 401 with no key and with a made-up key, 402 for a Register key on a
Cell-gated route, the CORS preflight for `https://neuralbridge.io` (override with
`REHEARSAL_ORIGIN`), http→https, certificate verification and days to expiry
(`--min-cert-days`, default 14), and that no response carries a provided secret or a
credential-shaped string. Exit 0 only if everything passed; 3 if something stayed
`UNCHECKED` (for example no `REHEARSAL_REGISTER_KEY`, or a plain-http target); 1 on
any failure. `--expect-purchasable` reads a boolean the API exposes, so it cannot tell a real
Stripe price id on the host from a placeholder price id: only a test checkout can. Full description and the other phases: `DEPLOY_NOW.md`.

The equivalent by hand, for one step at a time, is in `deploy/assurance/README.md`
("What to check after deploying").

## Part B — five checks from a real browser

Done from a real browser, not curl: the point is to prove the browser-side CORS and
JS wiring, which curl and the tool above cannot tell you. Use the **staging** site
(`DEPLOY_NOW.md` §4), built against the **staging** API, with the staging origin in
the API's `ASSURANCE_ALLOWED_ORIGINS` and `ASSURANCE_MARKETING_URL`. Run them again
after any change to the API, Stripe config, or `NEXT_PUBLIC_ASSURANCE_API_URL`.

1. **Live plans.** Visit `<staging site>/#pricing`. The pricing cards must show the
   "Live from `GET /v1/plans`" note, not silently sit on the static fallback.
2. **Buy appears.** On Register or Cell, the button must read **Buy …**, not "Talk to
   sales" — that only happens once `purchasable` comes back true from the live API.
3. **Playground Validate.** On the homepage, submit the free Validator playground.
   It must return a real response (missing-field issues), not the "Not deployed
   publicly yet" message.
4. **Checkout success path.** Click Buy, enter an email, and pay with Stripe's
   **test card** (`4242 4242 4242 4242`, any future expiry, any CVC) on a test-mode
   Stripe account. You should land on `<staging site>/checkout/success` and see a
   one-time API key within a few seconds. (A real card must never be used for this.)
5. **CORS.** The same check as in Part A, but from the staging site's origin:
   ```bash
   curl -i -X OPTIONS https://<your-staging-app>.fly.dev/v1/plans \
        -H 'Origin: <staging site origin>' -H 'Access-Control-Request-Method: GET' \
        | grep -i access-control-allow-origin
   ```
   Must echo that origin exactly.

If all five pass and Part A has no `FAIL`, the **staging rehearsal** is complete. That
is not a go-live: it does not show that Stripe's real delivery reaches the endpoint
(use the dashboard's *Send test webhook*), that the image runs under load, or that
anyone will pay. If any check fails, fix the matching step in `DEPLOY_NOW.md` first.

Filling in real values (a hostname, test price ids, a test webhook secret) is
founder work; the tool and these checks do not need a code change to run, but a
first run may well find one.
