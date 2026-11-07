# SBOM drafts and CSAF supplier advisories

Two documents arrive from outside: a software bill of materials from whoever built a
machine's software, and a security advisory from whoever supplies a component. Neither is
evidence about a particular machine until a person says so. This guide covers how each is read,
what is recorded, what is a draft, and what only a named person can do.

```bash
# a CycloneDX SBOM -> a DRAFT inventory (nothing is enrolled, nothing is marked safety-relevant)
assurance ingest sbom-import  sbom.cdx.json --ledger register.db --name "sbom.cdx.json"
assurance ingest sbom-list    --ledger register.db
assurance ingest sbom-show    sbom-9f637d11... --ledger register.db --review-template > review.json
#   ... a named person fills every decision in review.json ...
assurance ingest sbom-review  sbom-9f637d11... review.json --ledger register.db --actor "A. Integrator"

# a CSAF 2.0 advisory -> a recorded, unsigned supplier advisory, matched to the fleet
assurance ingest csaf-import  advisory.csaf.json --ledger register.db --name "advisory.csaf.json"
assurance ingest csaf-impact  csaf-103b65df... --ledger register.db
```

These are the same domain functions as `POST /v1/ingest/sbom`, `.../review`, `POST /v1/ingest/csaf`,
`GET /v1/ingest/csaf/{advisory_ref}/impact` and the MCP tools `sbom_import`, `csaf_import`,
`csaf_impact` (and the read tools). The command line works on a local ledger file and opens no
socket. Synthetic example documents are in `examples/ingest/`; every name, version and hash in
them is invented.

## 1. SBOM -> a draft inventory

`sbom-import` reads CycloneDX **JSON**, spec versions **1.4, 1.5 and 1.6**; any other version is
refused (`unsupported_spec_version`), never read as the nearest one.

### Validation

The CycloneDX JSON schemas are large and reference further schemas, so none is vendored here.
The importer applies the explicit structural rules below; **any** violation refuses the whole
document (nothing is recorded and nothing is guessed around). This is a structural check, not a
full schema validation: unknown fields are listed in the draft's `unrecognised_fields`, not
refused; licence, pedigree, evidence, dependency, composition and vulnerability content is not
examined; a signature on the document is not checked.

| Rule | |
|---|---|
| SBOM-R01 | the document is a JSON object |
| SBOM-R02 | `bomFormat` is exactly `CycloneDX` |
| SBOM-R03 | `specVersion` is present and one of 1.4, 1.5, 1.6 |
| SBOM-R04 | `serialNumber`, when present, is `urn:uuid:` and a lower-case UUID |
| SBOM-R05 | `version`, when present, is an integer of at least 1 |
| SBOM-R06 | `metadata` is an object; `metadata.timestamp` is ISO-8601 with a timezone |
| SBOM-R07 | `components` is an array of objects |
| SBOM-R08 | every component has a `type` from the enumeration of the declared `specVersion` |
| SBOM-R09 | every component has a non-empty string `name` |
| SBOM-R10 | `version`, `group`, `publisher`, `description`, `cpe`, `purl` are strings; `scope` is required, optional or excluded |
| SBOM-R11 | `bom-ref` is a non-empty string and **unique in the whole document** |
| SBOM-R12 | `hashes` is an array of `{alg, content}`; `alg` is a CycloneDX algorithm and `content` is hexadecimal of that algorithm's length |
| SBOM-R13 | `supplier`, when present, is an object whose `name` is a string |
| SBOM-R14 | at most 5,000 components, nested at most 8 deep |
| SBOM-R15 | text fields are at most 500 characters with no control, invisible or direction-changing character |

Also refused before anything is built: a document over 8 MiB (the HTTP API is bounded further by
its request-body cap, 1 MiB unless the operator raised it), JSON nested more than 40 deep (a CSAF document, whose product tree nests, may go to 140), a NUL
byte, text that is not UTF-8, `NaN`/`Infinity`, and a **repeated key inside one JSON object**
(two readers could take different values from it).

### What is recorded

Exactly what was supplied, and no more:

* the **SHA-256 of the document's bytes as received**, its size, and the source name, supplied
  timestamp and URL **as the caller stated them** (labelled unverified; a stated SHA-256 that
  differs from the bytes is refused `source_hash_mismatch`);
* the BOM's `serialNumber`, `version` and `metadata.timestamp` as supplied, and the subject
  component;
* every component's `type`, `bom-ref`, `group`, `name`, `version`, `purl`, `cpe`, `supplier`,
  `scope` and hashes as supplied, with its JSON path.

The document itself is not stored: the SHA-256 lets anyone confirm a file is the one imported.
The same bytes again are `already_imported` and write nothing.

### What the draft never does

| An SBOM cannot establish | So the draft |
|---|---|
| the machine's serial number | **never has one.** `proposed_identity.serial` is always empty; manufacturer and model are *candidates* the document names (with where it named them). A person types all three at review, and a serial equal to the SBOM's own `serialNumber` or its subject's `bom-ref`, or a placeholder (`n/a`, `tbd` ...), is refused |
| which software is necessary for safe operation | marks **nothing** safety-relevant: `safety_relevance` is `not_assessed` and `implements` is empty on every component, whatever its type or name |
| that anything was read off a unit | records every component with the hash source `declared`, the lowest the model has. A SHA-256 in the SBOM is kept as a declared digest, not as evidence about a unit; no component can be `read_from_machine` |
| a version, purl, supplier or digest it does not carry | records it as **unknown** (`null`, and named in the component's `unknown` list). A version is not taken from a purl, a purl is not built from a name, a supplier is not taken from a `group`, two different SHA-256 values are ambiguous and neither is used |
| completeness | says so: software absent from the SBOM is absent from the draft |

Every mapping and every safety-relevance decision is `pending_review`. The draft is a record of
kind `ingest.sbom_draft` in the account's ledger: unverified, low confidence. Nothing reads it as a
manifest; no coverage, fleet, advisory or passport function looks at it.

### The review (a named person)

`sbom-show --review-template` prints a review request with **every decision left `null`**. A
request that still holds one is refused, so a draft cannot be approved by submitting its own
template. The reviewer supplies:

* `decision`: `approve` or `reject`, and a `reason`;
* `identity`: manufacturer, model and **serial number** (and optionally site, owner, year, country);
* `functions`: the safety functions that exist for this machine (id, description, required
  performance, the checks that verify each);
* for **every** component: `include` (true/false, not defaulted), and for an included one its
  `kind` (`firmware`, `safety_program`, `safety_configuration`, `parameter_set`, `library`),
  `implements` (declared function ids; an empty list says it implements none) and
  `modifiable_in_field`. A `version` or `supplier` may be filled in only where the SBOM gave none.

Approval **enrols the machine through the one enrolment front door**
(`assurance machinery enrol`): enrolment's own refusals (`configuration_differs`,
`identity_conflict`, a ledger chain that does not verify) apply unchanged, and then nothing is
recorded and the draft stays pending. The manifest is `as_declared` and every item is
`declared`, so its tier ceiling is the lowest (`profile`: a ceiling on what any claim from it
could be worth, printed in the receipt, not a result). Coverage joins verification bundles to the
declared configuration hash, so a verification bound to it can read `covered` (the shipped
workflow example is also a declared baseline); that says the run was made against the
configuration the reviewer declared, **not that the unit holds that software**. A manifest that
only declares is not a look at the unit (`not_a_look`): the fleet's as-found rules and
`change reverify` refuse it, and the re-verification of a case needs a recorded `as_found`
manifest whose every item was read off the unit. A review is made once; a rejected
draft stays rejected (import a corrected SBOM to start again). The review record names the draft,
the reviewer and every decision.

Over HTTP the review is a human decision: it needs an operator key with the `decider` role and an
account-level key is refused 403, exactly as for closing a case. It has no MCP tool.

## 2. CSAF 2.0 -> a supplier advisory

`csaf-import` extends the existing `fleet import-csaf` translator
(`assurance.fleet.csaf`) rather than parsing the product tree a second time: the same reader
produces the product definitions, now also with the SHA-256 hashes a publisher states for a
product. The translation to this product's advisory format is stored alongside (so
`assurance change assess-advisory` can use it, with its own unsigned-import safeguards), or the
reason there is none (a VEX with nothing affected, say).

### Validation

CSAF 2.0 structure, checked against these rules (again: not the full JSON schema, which is not
vendored). Any violation refuses the document.

| Rule | |
|---|---|
| CSAF-R01 | a JSON object with a `document` object |
| CSAF-R02 | `document.csaf_version` is exactly `2.0` |
| CSAF-R03 | `document.category` is `csaf_security_advisory` or `csaf_vex` |
| CSAF-R04 | `document.title` is a non-empty string |
| CSAF-R05 | `publisher` has a category (coordinator, discoverer, other, translator, user, vendor), a name and a namespace that is an absolute URI |
| CSAF-R06 | `tracking` has an id, a status (draft, final, interim), a version (integer or semantic version), `initial_release_date` and `current_release_date` (RFC 3339 with a timezone, current not before initial) and a `revision_history` that includes the version |
| CSAF-R07 | a security advisory or VEX has a `product_tree` and at least one vulnerability |
| CSAF-R08 | branches have a known category, a name and exactly one of `branches` and `product`; a product has a name and a `product_id` |
| CSAF-R09 | every `product_id` is defined **exactly once** |
| CSAF-R10 | vulnerabilities are objects; `cve` is `CVE-yyyy-nnnn`; `product_status` keys are CSAF's and hold lists of product ids |
| CSAF-R11 | every product id used anywhere in a vulnerability is defined in the product tree |
| CSAF-R12 | in one vulnerability a product is in at most one of: affected, not affected, fixed, under investigation |
| CSAF-R13 | at most 5,000 product definitions and 2,000 vulnerabilities (refused, never truncated); branches nest at most 64 deep |
| CSAF-R14 | stored or compared text has no control, invisible or direction-changing character |

A `draft` or `interim` document is refused (`document_not_final`) unless `--allow-draft` /
`allow_draft` is given; it is then recorded as **partial**, and it can state no `fixed` or
`not_affected` (it may still be withdrawn).

### What is recorded

The SHA-256 of the bytes as received; the source name, timestamp and URL as supplied; the
**publisher** exactly as written (`name`, `namespace`, `category`); the tracking `id`, `version`,
`status`, **initial and current release dates**; the TLP label; each product definition (vendor,
name, version or range, stated SHA-256 hashes, purl, cpe); and each vulnerability's CVE and its
`product_status` as the publisher wrote it. A product named in a status but defined only in
`full_product_names` or `relationships`, or whose branch path lacks a vendor, name or version, is
recorded as **uninterpreted** and the record is **partial**: it cannot be matched to a machine.
A document with the same publisher and tracking id but different bytes is kept as its own record
(`same_tracking_id_as` says so); none supersedes another here.

The record's trust is always `unsigned_inspect_only`. Nothing here authenticates the publisher.

### Matching a machine: `csaf-impact`

Every enrolled machine gets exactly one of five results. The vocabulary is closed.

| Result | Means |
|---|---|
| `affected` | a product the publisher lists as `known_affected`, `first_affected` or `last_affected` matches one of the machine's items with certainty |
| `under_investigation` | the same, for a product the publisher lists as under investigation |
| `fixed` | the same, for `fixed` / `first_fixed` |
| `not_affected` | the same, for `known_not_affected` |
| `unknown` | everything else, with a **reason code** |

A match is *certain* only when (a) the item's hash was **read off the unit** and equals a SHA-256
the publisher states for the product, or (b) the folded component name **and** supplier are equal
(`fold_text`: Unicode-normalised, case-folded; not fuzzy), and the item's version is covered by
the product's version or range. Everything else is `unknown`:

| Reason code | When |
|---|---|
| `not_named` | the document names none of the machine's components. This is **not** "unaffected" |
| `supplier_differs`, `supplier_missing` | the name matches and the supplier does not, or the item records none. "Example Controls" and "Example Controls GmbH" stay different |
| `version_not_covered` | the publisher names this product but not this version (or the version is outside a range it states). CSAF lists what is affected; a version it does not list is not thereby unaffected |
| `version_scheme_ambiguous` | the version or the range cannot be compared without guessing at a scheme. A range is compared **only** when both it and the item's version are dotted decimal numbers (at most four parts, no leading zeros, one leading `v` allowed) and the range is one clause or one lower-and-upper interval, optionally prefixed `vers:semver/`. `V2.001`, `3.8.2-rc1`, `2.x`, `All versions < 3.1` and `!=` are not interpreted |
| `version_missing` | the item records no version |
| `hash_mismatch` | the item's hash was read off the unit and differs from the hash the publisher states for the version the label names: neither affected nor clear |
| `status_conflict` | the publisher's statements about the item contradict each other |
| `not_addressed_by_vulnerability` | one vulnerability's `product_status` does not mention the item at all. Absence is not a statement |
| `document_not_final` | a `fixed` / `not_affected` withheld because the document is a draft or interim |
| `ledger_chain_unverified`, `look_incomplete` | a `fixed` / `not_affected` withheld because the ledger chain does not verify, or the latest look at the machine was incomplete or failed |

A hash the manifest carries that was **not** read off the unit (declared, or from a vendor) is not
compared: it says what should be there, not what is. A machine's result is the worst of its
items', in the order `affected`, `under_investigation`, `unknown`, `fixed`, `not_affected`. A
doubtful match to an `affected` product also prevents a `fixed`/`not_affected` result for the same
item. Each result carries the matched product ids, how the identity was established and the
document's provenance (SHA-256, publisher, tracking, ledger entry).

Exit codes: 0 every machine is fixed, not_affected or not named and nothing is incomplete; 1 at
least one machine is affected; 3 **not a clear** (a machine is under_investigation or unknown,
the advisory is partial, the fleet is empty or the ledger chain does not verify); 2 could not run.

### What the result is, and is not

Inspect-only: the document is unsigned third-party content, a match is a comparison of names,
labels and (where read from the unit) hashes, and `not_affected` and `fixed` are the publisher's
statements relayed, not a finding by this product that a machine is safe. Whether a safety
function is in question, and what to do, is a person's decision. Nothing here opens a case; to do
that use the existing, human-gated route with the stored translation
(`assurance change assess-advisory --accept-unsigned ...`, a named person's explicit override).

## 3. The surfaces

| Capability | CLI | HTTP | MCP |
|---|---|---|---|
| import an SBOM draft | `ingest sbom-import` | `POST /v1/ingest/sbom` | `sbom_import` |
| list / show drafts | `ingest sbom-list`, `sbom-show` | `GET /v1/ingest/sbom`, `.../{draft_id}` | `sbom_drafts`, `sbom_draft` |
| review a draft (human) | `ingest sbom-review` | `POST /v1/ingest/sbom/{draft_id}/review` | none, by design |
| import a CSAF advisory | `ingest csaf-import` | `POST /v1/ingest/csaf` | `csaf_import` |
| list / show advisories | `ingest csaf-list`, `csaf-show` | `GET /v1/ingest/csaf`, `.../{advisory_ref}` | `csaf_records`, `csaf_record` |
| the machine-by-machine result | `ingest csaf-impact` | `GET /v1/ingest/csaf/{advisory_ref}/impact` | `csaf_impact` |

Hosting (from the capability catalogue): all are `hosted_and_offline` -- served by the HTTP API on
the calling account's own ledger, and runnable offline on a local ledger file.

Permissions are those of the other machine and fleet routes that touch the account's ledger:
**401** with no or an invalid key, **402** for an authenticated account whose plan does not
include machine verification (Cell and above; no plan was changed), **403** for the review with an
account-level key or a non-decider operator. Entitlements are read on every request. The HTTP
`document` field carries the document as **text**: its UTF-8 bytes are what is hashed. Refusals
are `{"error": <code>, "detail": ..., "violations": [...]}`: `invalid_sbom`, `invalid_csaf`,
`too_large` (413), `too_deep`, `unsupported_spec_version`, `no_components`, `document_not_final`,
`invalid_source`, `source_hash_mismatch`, `invalid_review`, `already_reviewed` (409),
`configuration_differs` / `identity_conflict` (409), `draft_not_found` / `advisory_not_found`
(404).

## 4. A worked lifecycle (synthetic)

```
sbom-import  -> draft (pending_review)            nothing enrolled, no serial, nothing safety-relevant
sbom-review  -> a named person approves           machine enrolled via `machinery enrol`, declared only
machine verify --configuration-hash <hash>        a verification bound to that configuration
csaf-import  -> supplier advisory (unsigned)
csaf-impact  -> affected / unknown / ...          the machine, with reasons (exit 1: affected)
machinery record-change + change assess-intervention   a named person records the update; a case opens
                                                  and the function reads stale, not covered
change claim / advance                            ... a close now is refused: not ready_to_close
machine verify (new run) + machinery record-manifest (a look read off the unit)
change reverify                                   the declared manifest is refused; the look is accepted
change decide --actor <named person>              automation cannot close
csaf-impact                                       the firmware is fixed; what is still unknown stays
                                                  unknown (exit 3, not a clear)
machinery passport  ->  machinery check / machine check   an independent re-verification
```

`tests/test_assurance_ingest_lifecycle.py` runs this end to end on the synthetic documents in
`examples/ingest/`, and asserts that `unchecked`, `stale`, `unknown` and `degraded` are never read
as success along the way.

## 5. What this does not establish

* that an SBOM is complete, that it describes the machine in front of you, or which software is
  necessary for safe operation;
* the machine's identity: serial numbers are as typed by the reviewer and not authenticated to a
  physical unit;
* that a CSAF document is authentic, complete or current, or that a `not_affected` statement is
  right;
* anything about a component whose purl or CPE is the only identifier: purls and CPEs in an
  advisory are recorded but **not** used to match a machine (manifests carry no purl), and
  product `relationships` are not interpreted;
* revision handling: a later revision of an advisory is a separate record; none supersedes
  another.
