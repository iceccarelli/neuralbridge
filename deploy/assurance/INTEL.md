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
