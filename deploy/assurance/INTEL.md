# Public-source intelligence over HTTP and MCP (read-only)

`assurance intel` records KEV, NVD, EPSS and CSAF files as provenance-stamped, append-only
observations (`src/assurance/intel/`). The hosted API and the MCP server can **read** that
store. They cannot write it and they never fetch anything.

## The store is the operator's

* The path is the server setting `ASSURANCE_INTEL_STORE` (a file the operator builds with
  `assurance intel ingest` or `assurance intel refresh --live`, on their own machine or host).
* It is shared **public** data. It is not tenant evidence, lives in no tenant ledger, and is the
  same for every caller who is entitled to read it.
* Fetching and recording are an operator act. There is no ingest or refresh route and no such
  MCP tool, by design (`intel.ingest` and `intel.refresh` are CLI-only in
  `src/assurance/capabilities.py`, `by_design`).
* The routes open the file `mode=ro` with `query_only`; they never create it, never run its schema
  and cannot append. `tests/test_assurance_intel_api.py` checks the file's bytes are unchanged
  after calls.

## Routes (Cell tier, the `Machine` gate)

Same gate as the fleet, watch and change routes this data feeds: **401** with no or an invalid
key, **402** when authenticated but the plan lacks machine verification (read on every request).
No plan flag was added for intel.

```
GET /v1/intel/history?source=&limit=&after_seq=   observations, oldest first (limit 1-1000, default 200)
GET /v1/intel/observations/{seq}                   one observation in full (404 observation_not_found)
GET /v1/intel/cve/{cve_id}                         what every recorded source says about one CVE
GET /v1/intel/candidates                           advisory candidates + not_representable + conflicts
MCP tools (read-only): intel_history, intel_observation, intel_cve, intel_candidates
```

One route reads this store to open a case, for a named person only:
`POST /v1/change/assess/advisory/intel` (see `CHANGE.md`). It reads the store the same read-only
way, re-derives the candidate for the caller's own fleet, and opens the case as an
unauthenticated public-source, inspect-only advisory. It is not an MCP tool (`by_design`).

Ids are validated before the store is opened: `cve_id` must be `CVE-YYYY-NNNN...` (upper case,
ASCII digits), `seq` a positive integer, `source` one of `kev|nvd|epss|csaf`; otherwise **422**
(`invalid_cve_id`, `invalid_observation_seq`, `invalid_source`).

## What a response means

* **Provenance on every statement:** observation `seq`, `source`, `url`, `retrieved_at`,
  `sha256`, `feed_stamp`; each response's `sources_consulted` also names the `parser_version` of
  every observation used and lists the sources with no accepted observation.
* **No store is not "nothing known":** `no_intel_store_configured` (setting unset) and
  `intel_store_unreadable` (missing, not an intel store, or damaged) are **503**, following the
  attestation-key route. They are never an empty list. A store that exists but holds nothing
  answers `status: "empty"` with a note.
* **CVE enrichment:** KEV `listed` / `not_listed_in_kev` / `unchecked` (no catalogue recorded);
  EPSS `available` (with `score_date`, time-sensitive) / `unavailable` (never 0.0); NVD `present` /
  `rejected` / `unknown`; CVSS as published; NVD-versus-vendor `conflicts`. A CVE no recorded
  source mentions is `summary.status: "unknown"`, never clear.
* **`not_established`** travels with the answer: absence from KEV does not establish "not
  exploited"; a missing EPSS score is not a score; version ranges are not matched and no range
  arithmetic is done, so this never says a machine is or is not affected; a feed observation is
  unsigned (its sha256 shows which bytes were recorded, not that the source published them).
* **Candidates** are unsigned and inspect-only; severity defaults to `safety_relevant`; KEV never
  yields one. No candidate is not "no advisory exists".

## Configuring a deployment

Set `ASSURANCE_INTEL_STORE` to the store file (a persistent volume path on Fly). Nothing in this
repository sets it in production; doing so is the founder's deployment step. Refresh the store
with the CLI on the operator's side and ship/mount the file; the API sees new observations on
the next request.

## Refreshing CSAF vendor advisories live (operator CLI)

A vendor advisory describes a **product**. It does not say what any customer has installed, and
a fetched document is still an unsigned, inspect-only import: nothing here adds trust, and a
document is accepted only if the repo's own CSAF importer (`assurance.fleet.csaf`) accepts it.

```
python -m assurance intel refresh --source csaf --live --allow-host HOST [--allow-host ...] \
    --provider-metadata-url https://HOST/.../provider-metadata.json \
    [--max-documents 50] [--max-total-bytes 67108864] --store PATH
python -m assurance intel refresh --source csaf --live --allow-host HOST --url https://HOST/x.json \
    --store PATH                                    # one or more named documents
```

* **`--allow-host` is required** and exact (bare lower-case host names; no scheme, port, path or
  wildcard). Every URL touched must be https on one of those hosts, including each
  `directory_url` or ROLIE feed the provider's own metadata announces: a host the metadata names
  that the operator did not is refused, not followed. A URL with a query, fragment or userinfo is
  refused, so no credential can travel in a URL; csaf takes no API key and sends no credential.
  Redirects are followed only to the same host (the shared transport, unchanged); Retry-After is
  honoured by it; a 429/503 from the provider stops the batch.
* **Provider mode** reads `provider-metadata.json`, then `changes.csv` (path + last-change time) of
  the first announced `directory_url`, else `index.txt` (no times, so no incremental skipping),
  else a TLP:WHITE **ROLIE** JSON feed (`content.src` + `updated`; some providers, e.g. Siemens
  ProductCERT, announce only this). Index rows with an unusable path, link or time are counted
  and reported (`N index rows skipped`), never guessed.
* **Incremental**: no cursor is stored that could be corrupted. A document is skipped when this
  store already holds a *settled* observation of its URL whose recorded listing time is not older
  than the provider's current one. Newest first, at most `--max-documents` (default 50) per run,
  and `N more not fetched (max-documents reached)` is printed, so the next run continues; a
  `--max-total-bytes` cap (default 64 MiB, checked before each request) does the same. A
  transient failure (transport error, 429, 5xx) is recorded but not settled and is retried; a
  malformed or oversized document is recorded as `rejected` and settled until the provider lists
  it as changed. One bad document never aborts the batch.
* **Observations**: one per fetched document (`source csaf`, url, retrieved_at, http status, byte
  length, sha256, parser version) plus provenance kept beside it (provider metadata URL, listing
  time, publisher, and for an accepted document its own `tracking` id / version /
  initial_release_date / current_release_date). Same sha256 = `unchanged` (no downstream event);
  a revision of the same advisory (same URL, new sha256) is `changed` with the old observation
  and blob kept. `intel history` shows the tracking line; `--json` adds `provenance`.
* Missing `fixed` data stays unknown. `vers:` ranges are kept as text and never evaluated.
* Exit codes: 0 done, 1 something was rejected or refused, 2 could not run (no `--live`, no
  `--allow-host`, off-list host, unreadable metadata).

### `--allow-interim` (operator option, off by default)

Vendors such as Siemens ProductCERT publish ongoing advisories with `tracking.status: interim`.
By default these are refused and recorded `rejected` with the exact reason
`wrong_shape: tracking status is interim`; `refresh` and `ingest` end with
`N interim document(s) refused; pass --allow-interim to import them as inspect-only`, and
`intel history` repeats that count over the rows it lists.

`intel refresh --source csaf --live ... --allow-interim` and `intel ingest --csaf FILE
--allow-interim` (and `refresh_documents` / `refresh_provider` / `ingest_file` with
`allow_interim=True`) admit `interim` documents and only those:

* **`draft` stays refused** (`wrong_shape: tracking status is draft`). The importer's single
  `allow_draft` switch treats draft and interim alike; this layer does not, because a draft is a
  working copy the vendor has not published.
* A document refused for any other reason (bad shape, no reference, nothing mappable, ...) is
  still refused, with the importer's own reason; the option only removes the status check.
* The tracking status is kept verbatim (`provenance.tracking.status == "interim"`), and the
  provenance row carries `allow_interim: true` (a key in the existing append-only, trigger-guarded
  `provenance.meta_json`; no schema change, so existing stores need no migration). A refused
  interim document carries `interim_refused: true` so a later run with the option fetches it
  again instead of treating it as dealt with. A re-read of the stored bytes (candidates, API,
  watch) uses the recorded flag, so an interim payload without it is reported unreadable.
* Its candidate carries the note `tracking status was interim when read; the vendor may revise
  it` first in `notes`; the hosted `GET /v1/intel/candidates` and watch findings print `notes`
  unchanged, so the note reaches both. The import is marked partial, as the importer does.
* A later `final` revision of the same tracking id is `changed`, the interim observation stays in
  history, and the candidate (built from the newest accepted observation) drops the note.
* Trust is unchanged: `unsigned_inspect_only`, no automated consequence, a case still needs a
  named person and the unsigned-import override. The watch has no such option: it only reads
  the store.

The tests use a contract fixture (an in-memory provider on `csaf.example.invalid`); they are not
live integration. Each fetch of a ROLIE provider re-downloads its whole feed (no conditional
GET yet).
