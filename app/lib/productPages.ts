// The /product/<slug> pages, written once as data so the words can be reviewed and tested.
//
// Kept free of imports on purpose: tests/test_site_product_pages.py runs this file directly under Node
// (type stripping) to read the copy, and app/product/[slug]/page.tsx renders from the same objects, so
// what the test reads is what a visitor reads. Nothing here is a claim the code does not back:
//  - every capability id in `caps` / `statusCaps` must exist in public/capabilities.json, and the
//    page renders each one's CLI / API / MCP status straight from that file (never typed here);
//  - every `assurance ...` command, `METHOD /v1/...` route and MCP tool named in backticks must be
//    one the contract (or openapi.json) lists;
//  - the lower-case terms in VOCABULARY below are the only other snake_case words allowed in backticks,
//    and the test checks each appears in deploy/assurance/*.md.
// A string may contain `code` spans (backticks); there is no other markup.

export interface ProductStep {
  title: string;
  body: string;
  /** Capability ids (public/capabilities.json) this step relies on; each is linked to its row on the capabilities page (see capabilityHref). */
  caps?: string[];
}

export interface ProductFaq {
  q: string;
  a: string;
}

export interface ProductDocLink {
  label: string;
  href: string;
}

export interface ProductPage {
  slug: string;
  /** Short name for menus and breadcrumbs. */
  name: string;
  /** The search intent this page answers, as a short phrase (menu and search-index blurb). */
  intent: string;
  /** <title>, 60 characters or fewer, unique across the product pages. */
  title: string;
  /** Meta description, 120 to 160 characters, unique. */
  description: string;
  kicker: string;
  h1: string;
  /** One plain sentence. */
  definition: string;
  problem: string[];
  workflow: ProductStep[];
  youGet: string[];
  notEstablished: string[];
  whoActs: string[];
  statusNote: string;
  /** Capabilities whose per-surface status the page tabulates, read from the contract at render time. */
  statusCaps: string[];
  /** Slugs of other product pages. */
  related: string[];
  docs: ProductDocLink[];
  faq: ProductFaq[];
}

/** Snake_case words that may appear in backticks although they are not MCP tool names. */
export const VOCABULARY = [
  'read_from_machine',
  'supplied_by_vendor',
  'read_from_ledger',
  'declared_by_holder',
  'hash_mismatch',
  'unsigned_inspect_only',
  'never_verified',
  'not_demonstrable',
  'ready_to_close',
  'covered_at_community',
  'no_attestation_key_configured',
  'actor_mismatch',
  'operator_required',
  'needs_review',
];

export const PRODUCT_BASE = '/product';
export const SITE_URL = 'https://neuralbridge.io';
const CAPABILITIES_PAGE = '/docs/capabilities';

export function productHref(slug: string): string {
  return `${PRODUCT_BASE}/${slug}`;
}

/** The anchor the /docs/capabilities page gives a capability row (app/docs/capabilities/page.tsx: `cap-<id>`). */
export function capabilityHref(id: string): string {
  return `${CAPABILITIES_PAGE}#cap-${id}`;
}

export const PRODUCT_PAGES: ProductPage[] = [
  // ---------------------------------------------------------------------------------------------
  {
    slug: 'industrial-autonomous-assurance',
    name: 'Industrial autonomous assurance',
    intent: 'What the product is: the lifecycle from machine to attestation',
    title: 'Industrial Autonomous Assurance: the machine lifecycle',
    description:
      'Machine safety evidence goes stale when the machine changes. How a ledger links machine, software, change, verification, intervention and attestation.',
    kicker: 'Category overview',
    h1: 'Industrial autonomous assurance: evidence that notices when the machine changed',
    definition:
      'Industrial autonomous assurance is a record, kept in a hash-chained ledger, of what is installed on a machine, which checks were run against it and when, so that a later change shows which of those checks no longer apply.',
    problem: [
      'A safety assessment describes a machine on one day. After that day a technician updates firmware, a PLC project is patched, a safety-controller parameter is edited, a scanner zone is moved, or a supplier publishes an advisory about a component. Each of these can make the earlier assessment describe a machine that no longer exists, and nothing in a folder of PDFs says so.',
      'The repository’s own guides give the shape of the failure: a protective-stop function verified in February, a safety-controller firmware replaced in March, and no sealed verification since. The sign-off still exists; it simply stopped applying. Detecting that is a join across records that normally live in four different places, which is why it is usually skipped.',
    ],
    workflow: [
      {
        title: 'Machine',
        body: 'A named person enrols the machine with `assurance machinery enrol`. Its identity is the key manufacturer/model#serial, as declared; nothing authenticates it to a physical unit.',
        caps: ['machinery.enrol'],
      },
      {
        title: 'Configuration',
        body: 'Enrolment seals a manifest and returns a receipt carrying the configuration hash. A later manifest that differs is drift, reported by `assurance machinery diff`, never a silent re-enrolment.',
        caps: ['machinery.diff', 'machinery.manifest'],
      },
      {
        title: 'Software',
        body: 'The manifest lists safety-relevant software items, which safety function each implements, and where each hash came from: read from the machine, supplied by the vendor, or merely declared. An item with no hash is reported uncomparable, never unchanged.',
      },
      {
        title: 'Evidence',
        body: 'Everything is appended to a per-account ledger whose records are hash-chained. `GET /v1/ledger/verify` and `assurance art14 verify` walk the chain.',
        caps: ['evidence.ledger_verify'],
      },
      {
        title: 'Change',
        body: 'A divergence, a recorded intervention or a supplier advisory becomes a change-assurance case with an owner: `assurance change assess-drift`, `assurance change assess-intervention`, `assurance change assess-advisory`.',
        caps: ['change.assess_drift', 'change.assess_intervention', 'change.assess_advisory'],
      },
      {
        title: 'Verification',
        body: '`assurance machine verify` checks a recorded run against a declared safety envelope. The result carries a tier, and `unchecked` is a valid outcome.',
        caps: ['machine.verify'],
      },
      {
        title: 'Finding',
        body: '`assurance machinery coverage` states, per safety function, whether verification is current, stale, failing, unchecked, incomplete or never done.',
        caps: ['machinery.coverage'],
      },
      {
        title: 'Intervention',
        body: 'A technician’s change is recorded with `assurance machinery record-change`, naming the item touched. That record is what dates a verification as no longer applying.',
        caps: ['machinery.intervention'],
      },
      {
        title: 'Attestation',
        body: 'A signed ledger head (`assurance attest sign`) and a sealed passport (`assurance machinery passport`) let someone else check the position without trusting the account holder’s database.',
        caps: ['attest.sign', 'machinery.passport'],
      },
    ],
    youGet: [
      'The artefacts are a sealed manifest, a receipt, verification bundles, a case export, a passport and a signed ledger head. A passport is re-checked by anyone with `assurance machinery check` or `POST /v1/machinery/passport/check`; a bundle with `assurance machine check`; an evidence file with `assurance evidence verify`. The checks run without an account because the audience is a reviewer, not the account holder.',
      'Each of the pages below takes one question from this lifecycle and answers it in full: the ledger, continuous change handling, supplier advisories, the two regulations, machine verification, attestation, the offline kit, the interfaces and file-based integration.',
    ],
    notEstablished: [
      'That any machine is safe. Coverage says a recorded verification still applies to a declared function, not that the function works.',
      'That the declared identity is a physical unit, or that a manifest lists every safety-relevant item.',
      'That a record was true when written. A ledger is custody of what was filed.',
      'That anything complies with a regulation or has passed a conformity assessment. No step in this lifecycle decides that.',
    ],
    whoActs: [
      'Software drafts and reports: it compares manifests, computes coverage, opens cases from machine data and prepares evidence. Named people decide: they enrol, record interventions, submit re-verification, and close, reject or defer a case. The domain layer refuses an actor that is not a named person; it cannot prove who typed the name.',
    ],
    statusNote:
      'Available means the command, route or tool exists in this build; it does not mean a hosted deployment is running. Nothing here has been deployed to production, and the hosted counter-signature has no service key configured today.',
    statusCaps: [
      'machinery.enrol',
      'machinery.diff',
      'machinery.coverage',
      'machinery.passport',
      'machine.verify',
      'change.assess_drift',
      'evidence.ledger_verify',
      'attest.sign',
    ],
    related: [
      'machine-evidence-ledger',
      'continuous-machine-assurance',
      'supplier-advisory-fleet-impact',
      'cra-article-14',
      'machinery-regulation-evidence',
      'machine-safety-verification',
      'evidence-attestation',
      'offline-assurance-kit',
      'assurance-api-and-mcp',
      'enterprise-integration',
    ],
    docs: [
      { label: 'Assurance engines overview', href: '/docs/assurance' },
      { label: 'Capabilities by surface', href: '/docs/capabilities' },
    ],
    faq: [
      {
        q: 'What problem does this solve?',
        a: 'A safety assessment is true of a machine on one day. When firmware, a PLC project or a safety-controller setting changes afterwards, the assessment may stop describing the machine, and the ledger dates when that happened.',
      },
      {
        q: 'Does this make a machine or a manufacturer compliant?',
        a: 'No. It keeps evidence and drafts documents. Regulatory duties, filings and conformity assessment remain with the manufacturer and the people it names.',
      },
      {
        q: 'Who can check the evidence?',
        a: 'Anyone. Passports, verification bundles, evidence files and attestation logs can be re-checked without an account, using the CLI, the HTTP API, or the free check page.',
      },
      {
        q: 'Is it deployed?',
        a: 'No production deployment exists. The commands run from the repository, and the status page lists what has been prepared but not performed.',
      },
    ],
  },
  // ---------------------------------------------------------------------------------------------
  {
    slug: 'machine-evidence-ledger',
    name: 'Machine evidence ledger',
    intent: 'A hash-chained, per-account evidence ledger and what a chain cannot detect',
    title: 'Machine evidence ledger: hash chain, anchors, backups',
    description:
      'A hash-chained ledger catches edits but not deleted tail records. How signed anchors, completeness reporting, backups and verify close that gap.',
    kicker: 'Evidence ledger',
    h1: 'The machine evidence ledger: what a hash chain proves and what it misses',
    definition:
      'A machine evidence ledger is an append-only record in which every entry carries a hash that depends on the entry before it, so that editing any record breaks the chain from that point on.',
    problem: [
      'Machine evidence is only useful if a reviewer can tell it was not rewritten after the fact. A hash chain answers part of that: change a record and every link after it stops matching, and verification names the sequence number.',
      'The repository’s attestation guide states the part a chain does not answer. It does not detect removal. An administrator with write access to the database can rewind the ledger, drop the last records, append afresh, and hand over a ledger that verifies perfectly. This is a property of chains in general, not a defect of one implementation, and the guide says so.',
    ],
    workflow: [
      {
        title: 'One account, one ledger, one writer',
        body: 'Each account’s evidence lives in its own ledger file; the shared operator ledger is separate and is not tenant data. Exactly one writer touches a ledger file, because two writers would fork the chain.',
      },
      {
        title: 'Verify the chain',
        body: '`assurance art14 verify` and `GET /v1/ledger/verify` walk the whole chain; the MCP tool `ledger_verify` does the same read. A ledger whose chain does not verify is never reported clear: fleet reports over it read `needs_review`.',
        caps: ['evidence.ledger_verify'],
      },
      {
        title: 'Check a file you were handed',
        body: '`assurance evidence verify` and `POST /v1/evidence/verify` re-check an export or bundle and store nothing. Exit 0 verified, 1 does not verify, 2 unreadable, 3 nothing inconsistent was found but something asked for is not established.',
        caps: ['evidence.verify'],
      },
      {
        title: 'Anchor the head',
        body: 'A signature over the ledger head, made by a key the database holder does not have, turns a rewind into a visible contradiction. `assurance attest sign` records it in an attestation log; `assurance attest verify --ledger` asks whether the ledger still holds every signed head.',
        caps: ['attest.sign', 'attest.verify'],
      },
      {
        title: 'Report completeness honestly',
        body: 'An export checked without a trusted public key reports completeness as not checked and exits 3, never as a pass. With a signed head but no skeleton it is also exit 3. An anchor covers nothing appended after it.',
      },
      {
        title: 'Back up, then prove the restore',
        body: '`assurance ops cycle` takes a backup of every ledger into a new directory and verifies it at once; the manifest records each ledger’s length and head link hash. The operations guide says a backup is only a backup once a restore has been shown to work, and prescribes a drill on a scratch copy.',
        caps: ['ops.cycle', 'ops.status'],
      },
      {
        title: 'Export for someone else',
        body: '`assurance tenant export` writes the ledger, a whole-ledger evidence bundle and the attestation log into a manifest-hashed directory, and `assurance tenant verify-export` re-hashes it.',
        caps: ['tenant.export', 'tenant.verify_export'],
      },
    ],
    youGet: [
      'You get a ledger that detects editing on its own, and detects removal once a head has been signed and kept outside the database. The artefacts are the ledger file, an evidence bundle, an attestation log and a backup manifest.',
      'A third party can check an export without installing the product: `scripts/verify_export_standalone.py` uses only the Python standard library, reads end to end, opens no network connection, and is deliberately narrower than the product verifier. It exits 0 only with a trusted public key and a signed head that the signer read from the ledger; otherwise it says completeness was not checked.',
    ],
    notEstablished: [
      'That a chain with no signed head is complete. Without an anchor, deletion of the tail is undetectable and completeness is reported as not checked.',
      'That records appended since the last attestation are intact; they rest on the chain alone until the next signature.',
      'That the records were true when written. Custody is not content.',
      'That a hosted export is anchored. It embeds an anchor only if the operator signed a head read from that account’s own ledger; until then its completeness is not checked.',
      'That a restored backup is current: anything appended after the backup is lost, and the guide says to record that.',
    ],
    whoActs: [
      'Software appends, hashes, verifies and reports. People decide when to sign, who holds the key and how often to anchor: the attestation guide says to sign on a cadence matching how much history you are willing to lose the ability to defend. Restore drills and retention are the operator’s decisions; the product deletes nothing automatically.',
    ],
    statusNote:
      'The verification surfaces are available on the CLI, the HTTP API and MCP. Backup and export tooling is operator tooling on the CLI only, by design. Hosted counter-signing needs a service key that no deployment has today.',
    statusCaps: [
      'evidence.ledger_verify',
      'evidence.verify',
      'attest.sign',
      'attest.verify',
      'attest.log',
      'ops.cycle',
      'tenant.export',
      'tenant.verify_export',
    ],
    related: ['evidence-attestation', 'continuous-machine-assurance', 'offline-assurance-kit', 'enterprise-integration'],
    docs: [
      { label: 'Attestation guide', href: '/docs/assurance/attest' },
      { label: 'Check an evidence file', href: '/verify' },
    ],
    faq: [
      {
        q: 'Does a hash chain stop someone deleting records?',
        a: 'No. A chain detects editing. Deleting the newest records and rebuilding the chain from the start yields a ledger that verifies. Only a signed head, made by a key the database holder lacks and kept elsewhere, exposes it.',
      },
      {
        q: 'What does verifying an unsigned export tell me?',
        a: 'That the file is internally consistent. Completeness is reported as not checked, with exit 3, because anyone holding the file could rebuild a consistent chain with entries left out.',
      },
      {
        q: 'Where does tenant data live?',
        a: 'In a ledger per account. The shared ledger belongs to the operator and is not tenant data.',
      },
      {
        q: 'Does the product delete old ledgers?',
        a: 'No. The only code path that removes a tenant’s files is an explicit delete run by a named operator after a verified export.',
      },
    ],
  },
  // ---------------------------------------------------------------------------------------------
  {
    slug: 'continuous-machine-assurance',
    name: 'Continuous machine assurance',
    intent: 'The cycle from enrolment to passport, and how staleness is detected',
    title: 'Continuous machine assurance: enrol, watch, re-verify',
    description:
      'The operating cycle: enrol, seal a manifest, verify, detect change, find stale evidence, re-verify, record the intervention and issue a passport.',
    kicker: 'Operating cycle',
    h1: 'Continuous machine assurance: from enrolment to a passport that can go stale',
    definition:
      'Continuous machine assurance is the repeated cycle of enrolling a machine, recording what it runs, verifying it, noticing configuration drift and re-verifying, with each step written to a ledger and each judgement left to a named person.',
    problem: [
      'A one-off assessment decays as configuration drift accumulates. The repository’s watch guide describes the dull reality: a firmware update tomorrow strands every sign-off in the ledger, and nothing says so until someone runs the comparison again. A job that quietly stops looks identical to a quiet week.',
      'So the cycle has two jobs. It must notice change on a schedule, and it must make a failure to look distinguishable from nothing having moved. The watch command uses three exit codes for this: 0 quiet, 1 something for a person to read, 2 it could not rely on its inputs.',
    ],
    workflow: [
      {
        title: 'Enrol',
        body: '`assurance machinery enrol` declares the machine, seals its manifest and returns a receipt that lists every safety function as `never_verified` until a verification exists.',
        caps: ['machinery.enrol'],
      },
      {
        title: 'Manifest',
        body: '`assurance machinery record-manifest` seals a new snapshot of the software. `assurance collect run` builds one from exported files, and labels them `supplied_by_vendor` unless an operator asserts `read_from_machine`.',
        caps: ['machinery.manifest', 'collect.run'],
      },
      {
        title: 'Verify',
        body: '`assurance machine verify` checks a recorded run against the declared envelope and, given a ledger and the machine’s key, seals the bundle there.',
        caps: ['machine.verify'],
      },
      {
        title: 'Detect change',
        body: '`assurance watch run` makes one pass over every target. `assurance machinery diff` grades a divergence: a hash moving on an item that implements a safety function is the finding; a version string moving over identical bytes is administrative.',
        caps: ['watch.run', 'machinery.diff'],
      },
      {
        title: 'Staleness',
        body: '`assurance machinery coverage` joins the change to the verification. An intervention names an item, the manifest says which functions the item implements, and a verification that started before the intervention no longer describes the machine.',
        caps: ['machinery.coverage'],
      },
      {
        title: 'Re-verify and decide',
        body: 'A person claims the case (`assurance change claim`), the work is done on the machine, a new run is verified, and `assurance change reverify` submits it. A re-verification can bring a case to `ready_to_close`; `assurance change decide` closes it and refuses a non-person.',
        caps: ['change.claim', 'change.reverify', 'change.decide'],
      },
      {
        title: 'Intervention',
        body: 'The technician’s change itself is sealed with `assurance machinery record-change`, so the record of what was touched exists before the verification is repeated.',
        caps: ['machinery.intervention'],
      },
      {
        title: 'Passport',
        body: '`assurance machinery passport` seals the machine’s whole evidence position; anyone re-checks it with `assurance machinery check`.',
        caps: ['machinery.passport', 'machinery.passport_check'],
      },
      {
        title: 'Run the unattended parts',
        body: '`assurance ops cycle` runs the non-human steps in a fixed order: optional intel refresh, watch, ledger verification, anchoring, backup and backup verification. `assurance ops status` exits 2 when the last cycle is older than its limit, so a dead scheduler is noticed by a reader elsewhere.',
        caps: ['ops.cycle', 'ops.status'],
      },
    ],
    youGet: [
      'You get a dated answer to the question that matters after any change: which safety functions still have a standing verification and which do not. The report names the function, the verification, the intervention that disturbed it and how many days the function has run without cover.',
      'The passport is the portable artefact. It carries a verdict (`covered`, `covered_at_community`, `gaps`, or an indeterminate result when the ledger chain does not verify), and its check is open to anyone, including an insurer or auditor who holds nothing but the file.',
    ],
    notEstablished: [
      'That the machine is physically safe. A passport reports recorded evidence, and a function is covered only when every check it declares has a current verification.',
      'That the manifest is complete. The passport itself says the manifest is not confirmed complete.',
      'That anything was happening between runs. A run records one moment, and a watch with no maximum age does not check that its source store is fresh.',
      'That a closed case means the machine is safe. Closed means a named person decided it, for the reason they wrote.',
    ],
    whoActs: [
      'The scheduler and the software detect, compare, open cases from machine data, and prepare reports. A named person claims a case, records the intervention, supplies the re-verification and makes the closing decision. The cycle record lists the human actions it raised; it cannot tell whether anyone acted on them.',
    ],
    statusNote:
      'Every step above exists as a CLI command. Opening a case from public intelligence, closing a case and recording an enrolment have no MCP tool by design; the table shows each surface.',
    statusCaps: [
      'machinery.enrol',
      'machinery.manifest',
      'watch.run',
      'machinery.coverage',
      'change.reverify',
      'change.decide',
      'machinery.passport',
      'ops.cycle',
    ],
    related: ['machine-evidence-ledger', 'machine-safety-verification', 'machinery-regulation-evidence', 'supplier-advisory-fleet-impact'],
    docs: [
      { label: 'Operator pipeline', href: '/docs/assurance/pipeline' },
      { label: 'Change assurance', href: '/docs/assurance/change' },
      { label: 'Watch', href: '/docs/assurance/watch' },
    ],
    faq: [
      {
        q: 'How is a stale verification detected?',
        a: 'By a mechanical join: an intervention names the item it touched, the manifest says which functions that item implements, and a verification whose run started before the intervention is marked stale for those functions.',
      },
      {
        q: 'What does exit code 2 from the watch mean?',
        a: 'It could not rely on a source or store, including a store older than its configured limit. It never shares a code with nothing moved.',
      },
      {
        q: 'Can the cycle close a case?',
        a: 'No. A re-verification can bring a case to ready to close. Closing needs a named person and a written reason.',
      },
      {
        q: 'Does the cycle fetch anything from the internet?',
        a: 'Only the public-source refresh does, and only with both live set in the configuration and the live flag on the command line. Without them nothing opens a socket.',
      },
    ],
  },
  // ---------------------------------------------------------------------------------------------
  {
    slug: 'supplier-advisory-fleet-impact',
    name: 'Supplier advisory fleet impact',
    intent: 'Which enrolled machines does a supplier advisory touch, and how much to trust it',
    title: 'Supplier advisory fleet impact: CSAF, KEV, NVD, EPSS',
    description:
      'A vendor advisory describes a product, not what you installed. How advisories are matched to enrolled machines by hash, with signed and unsigned kept apart.',
    kicker: 'Advisories and fleet impact',
    h1: 'Supplier advisories and fleet impact: matching a product notice to the machines you enrolled',
    definition:
      'Supplier advisory fleet impact is the question of which enrolled machines an advisory touches, answered from what each manifest records and graded by how far the advisory itself can be trusted.',
    problem: [
      'A component advisory usually reaches an integrator as an email or a PDF. The supplier guide shows why that is a hazard: a forged message urging a flash of the safety controller is, if believed, a physical safety incident delivered by email, and the usual defence is recognising the sender’s writing style.',
      'Even a genuine advisory describes a product and its versions. It does not say which firmware is installed on a given controller at a given site. Answering that is a join between the advisory and the manifests of enrolled machines, and the join has to say how sure it is.',
    ],
    workflow: [
      {
        title: 'Record public sources',
        body: '`assurance intel ingest` records local KEV, NVD, EPSS and CSAF files as provenance-stamped, append-only observations. `assurance intel refresh --live` fetches one source from its official host and is the only networked step.',
        caps: ['intel.ingest', 'intel.refresh'],
      },
      {
        title: 'Read what is known',
        body: '`assurance intel show` reports what every recorded source says about a CVE. KEV not listed is not “not exploited”; an EPSS value with no score is unavailable, not zero; a CVE no source mentions is `unknown`, never clear.',
        caps: ['intel.show', 'intel.history', 'intel.candidates'],
      },
      {
        title: 'Translate, inspect only',
        body: '`assurance fleet import-csaf` converts a CSAF 2.0 advisory into this product’s format. The result is `unsigned_inspect_only` and may be partial; a partial advisory is never clear.',
        caps: ['fleet.import_csaf'],
      },
      {
        title: 'Prefer a signed feed',
        body: 'A supplier signs advisories into a hash-chained feed (`assurance supplier publish`). `assurance supplier verify` and `assurance supplier trust check` judge it under keys you pinned. `fleet advisory` refuses a feed that does not verify.',
        caps: ['supplier.publish', 'supplier.verify', 'supplier.trust_check', 'fleet.advisory_signed'],
      },
      {
        title: 'Match against the fleet',
        body: '`assurance fleet advisory` matches by hash first, then version, then name, and always reports the basis. Matching by version label is a probable match; a label that names an affected version over bytes the supplier did not list is `hash_mismatch`, the contradictory case. `assurance fleet advisory-check` asks the same of one machine without a ledger.',
        caps: ['fleet.advisory', 'fleet.advisory_check'],
      },
      {
        title: 'Hand to a person',
        body: '`assurance watch open-case` opens a case from a public finding only for a named person, and an unsigned import also needs an explicit acceptance and a reason. A signed advisory from a pinned key can open a case without a named person; closing stays human.',
        caps: ['watch.open_case', 'change.assess_advisory', 'change.assess_advisory_signed'],
      },
    ],
    youGet: [
      'You get an impact report naming each machine, the basis of the match, the safety functions newly in question and the machines that are neither confirmed affected nor confirmed clear. Field 5 of an Article 14 draft is assembled only from confirmed machines.',
      'Every observation keeps its source, retrieval time, hash and parser version, so a reviewer can ask what a host said at a given time. A revised advisory is recorded as changed, with the older observation kept.',
    ],
    notEstablished: [
      'That an advisory is genuine, correct, complete or current. A fetch that succeeded records what a host said at that time.',
      'That a machine is affected or unaffected. `fleet advisory` matches the labels in a sealed manifest and does no version-range arithmetic. The CSAF import (`ingest csaf-impact`) compares dotted-decimal ranges only, and a range it cannot read is `unknown`, never a match.',
      'That an empty fleet, or no match, means the fleet is clear. A report over an empty fleet says no machine was assessed.',
      'That the supplier’s key belongs to the supplier. The fingerprint has to arrive by a route the advisories do not travel on.',
      'That silence from a supplier is safety: a supplier that has not noticed a vulnerability publishes nothing, and signing cannot detect that.',
    ],
    whoActs: [
      'Software ingests, translates, matches and drafts. A person pins the supplier key, accepts an unsigned import with a reason, opens a case, decides awareness and closes. Fetching a feed is an operator act on the operator’s own machine; the hosted routes and MCP tools only read the operator’s store.',
    ],
    statusNote:
      'Ingest and refresh are CLI-only by design. The signed advisory case route exists on the HTTP API; its CLI verb is planned. Read-only intel routes answer 503 until an operator configures a store.',
    statusCaps: [
      'intel.ingest',
      'intel.refresh',
      'intel.show',
      'fleet.import_csaf',
      'fleet.advisory',
      'fleet.advisory_check',
      'supplier.trust_check',
      'change.assess_advisory_signed',
      'watch.open_case',
    ],
    related: ['cra-article-14', 'continuous-machine-assurance', 'enterprise-integration', 'evidence-attestation'],
    docs: [
      { label: 'Fleet advisory', href: '/docs/assurance/fleet' },
      { label: 'Supplier feeds', href: '/docs/assurance/supplier' },
      { label: 'Public-source intelligence', href: '/docs/assurance/intel' },
    ],
    faq: [
      {
        q: 'Does a vendor advisory tell me what my machine runs?',
        a: 'No. It describes a product and versions. What a particular controller runs is what its manifest records, and a manifest item with no hash can only be matched by label.',
      },
      {
        q: 'Is an empty result a clear result?',
        a: 'No. Nothing matched is not the same as nothing affected. A partial advisory, an uncomparable item or a ledger whose chain does not verify each prevent a clear answer.',
      },
      {
        q: 'What is the difference between signed and unsigned?',
        a: 'A signed feed verifies under a key you pinned and can open a case without a named person. An unsigned import, such as a CSAF translation, is inspect-only and needs a named person’s explicit acceptance.',
      },
      {
        q: 'Does absence from the KEV catalogue mean a vulnerability is not exploited?',
        a: 'No. The tool states that explicitly, and an EPSS score is time-sensitive and may be unavailable.',
      },
    ],
  },
  // ---------------------------------------------------------------------------------------------
  {
    slug: 'cra-article-14',
    name: 'CRA Article 14',
    intent: 'Article 14 clocks, awareness, triage reasoning and what a person must decide',
    title: 'CRA Article 14 reporting clocks, awareness and triage',
    description:
      'Article 14 of the Cyber Resilience Act sets 24-hour and later deadlines. How a register tracks the clocks while awareness, triage and filing stay human.',
    kicker: 'Regulation (EU) 2024/2847',
    h1: 'CRA Article 14: keeping the clocks, the reasoning and the human decisions on record',
    definition:
      'Article 14 of the Cyber Resilience Act obliges a manufacturer to report actively exploited vulnerabilities and severe incidents through the ENISA single reporting platform to the CSIRT designated as coordinator and to ENISA, on fixed deadlines, and a register is the record that shows when each clock started and why.',
    problem: [
      'Article 14 has applied since 11 September 2026, and Article 69(3) extends the duty to products placed on the market before 11 December 2027. For an actively exploited vulnerability the first deadline is 24 hours from awareness, and the early warning must indicate, where applicable, the Member States where the manufacturer knows the product has been made available (Art. 14(2)(a)).',
      'The clocks are easy to get wrong. The code documents six deadlines across two tracks, started by three different facts. The vulnerability final report runs 14 days from the date a corrective or mitigating measure became available, so a documented workaround starts it. The incident final report runs one calendar month from submission of the 72-hour notification. The code also records that the reporting platform currently displays the 72-hour counter as 48 hours after the early warning.',
    ],
    workflow: [
      {
        title: 'Open a case with the first signal',
        body: '`assurance art14 signal` records what anyone first heard. `assurance bridge art14` drafts an intake from an advisory and the enrolled fleet; it leaves the notification type and the awareness time blank on purpose.',
        caps: ['art14.signal', 'art14.bridge'],
      },
      {
        title: 'Record availability',
        body: '`assurance art14 availability` attaches the product and the Member States. The bridge assembles field 5 from the serial numbers of confirmed machines and exits non-zero when it cannot complete it.',
        caps: ['art14.availability'],
      },
      {
        title: 'Establish awareness',
        body: '`assurance art14 awareness` records when and by whom awareness was established, with the reasoning. Awareness is a determination after an initial assessment, not the moment an email arrived. No deadline runs before it is recorded.',
        caps: ['art14.awareness'],
      },
      {
        title: 'Work the triage',
        body: '`assurance art14 triage` takes the reportability questions in order. Every one is undetermined until a human answers, and a negative outcome records its ground, its authority and a reopen trigger where the ground can stop being true.',
        caps: ['art14.triage'],
      },
      {
        title: 'Watch the clocks',
        body: '`assurance art14 register` shows readiness across cases, worst first, and exits 1 on a missed or overdue deadline. `assurance art14 measure` records a corrective or mitigating measure, which starts the 14-day clock.',
        caps: ['art14.register', 'art14.measure', 'art14.breaches'],
      },
      {
        title: 'Check the draft, then record the filing',
        body: '`assurance art14 validate` and `POST /v1/spec/validate` check a draft against the platform field specification without recording it. `assurance art14 file` records a submission that has been validated against that specification; the register refuses a filing until a track and an awareness time exist.',
        caps: ['art14.validate', 'art14.filing', 'art14.fields'],
      },
      {
        title: 'Notify users and export',
        body: '`assurance art14 notify-users` records the Article 14(8) notification to users, and `assurance art14 export` produces a verifiable evidence bundle for the case.',
        caps: ['art14.user_notification', 'art14.export'],
      },
    ],
    youGet: [
      'You get a case record in which each deadline is computed from a stated start, each awareness decision carries its reasoning, each triage outcome cites its ground, and the whole is hash-chained. The export is a bundle someone else can re-check with `assurance evidence verify`.',
      'The free validator checks a draft against the 39-field specification and flags territories that are not EU Member States, such as Switzerland, before anyone opens the platform.',
    ],
    notEstablished: [
      'That a vulnerability is reportable, that exploitation is malicious or reliable, or that awareness was established when the record says. Those are judgements made by people.',
      'That a filing was made or accepted. The register records a submission; the manufacturer files on the reporting platform.',
      'That the product, or the organisation, meets any obligation. Nothing here decides legal or regulatory status.',
      'That the person named as awareness-holder is that person. A name is recorded as declared.',
    ],
    whoActs: [
      'The obligation is the manufacturer’s. The product features that help are the case record, the clock arithmetic, the field specification check and the drafts. The human decisions are awareness, the Article 14 track, each triage answer and case closure. The filing is made by the manufacturer on the reporting platform. Conformity assessment is a separate matter that Article 14 reporting does not involve, and the software here drafts and records without filing anything or assessing conformity.',
    ],
    statusNote:
      'Awareness has no MCP tool, by design, because it is a named person’s determination. Reads such as the register, breaches, a case and an export are available on MCP. Nothing is deployed to production.',
    statusCaps: [
      'art14.signal',
      'art14.awareness',
      'art14.triage',
      'art14.register',
      'art14.measure',
      'art14.validate',
      'art14.filing',
      'art14.export',
    ],
    related: ['supplier-advisory-fleet-impact', 'machinery-regulation-evidence', 'assurance-api-and-mcp', 'machine-evidence-ledger'],
    docs: [
      { label: 'The 24-hour field (bridge)', href: '/docs/assurance/bridge' },
      { label: 'Compliance officer view', href: '/solutions/compliance-officer' },
    ],
    faq: [
      {
        q: 'When does the 24-hour clock start?',
        a: 'At awareness, which a person establishes after an initial assessment. The register records the time and the reasoning, and shows no running deadline until awareness is recorded.',
      },
      {
        q: 'Does the software file the early warning?',
        a: 'No. It drafts, validates against the field specification and records a submission. The filing is the manufacturer’s act on the reporting platform.',
      },
      {
        q: 'What starts the final-report clock?',
        a: 'For a vulnerability, a corrective or mitigating measure becoming available, within 14 days. For an incident, submission of the 72-hour notification, with one calendar month to follow.',
      },
      {
        q: 'Can triage conclude that something is not reportable?',
        a: 'Only as a recorded decision naming its ground, and with a reopen trigger where that ground can stop holding. It never concludes silently.',
      },
    ],
  },
  // ---------------------------------------------------------------------------------------------
  {
    slug: 'machinery-regulation-evidence',
    name: 'Machinery Regulation evidence',
    intent: 'Annex III 1.1.9: software identity and intervention evidence for a machine',
    title: 'Machinery Regulation Annex III 1.1.9 software evidence',
    description:
      'Annex III 1.1.9 asks a machine to identify its safety software and collect evidence of intervention in it. How manifests and interventions keep that evidence.',
    kicker: 'Regulation (EU) 2023/1230',
    h1: 'Machinery Regulation evidence: identifying safety software and recording intervention',
    definition:
      'Annex III 1.1.9 of Regulation (EU) 2023/1230 requires a machine to identify the software installed on it that is necessary for it to operate safely and to collect evidence of intervention in, or modification of, that software or its configuration, and this page describes how a manifest and an intervention record serve that evidence.',
    problem: [
      'The regulation applies from 20 January 2027. The repository’s Annex III guide describes why doing this by hand is hard: the safety PLC program may be on a laptop, the scanner zones in a vendor tool, the robot’s safety parameters in the controller, and the only record that a technician changed any of them may be the technician’s memory.',
      'The Declaration of Conformity has the same drift problem. It describes the machine as it stood the day it was signed, and every later patch, scanner re-zone or PLC change is a day it may have stopped describing the machine.',
    ],
    workflow: [
      {
        title: 'Identify the software',
        body: 'A manifest lists safety-relevant items with supplier, version, kind, optional hash, and the safety functions each implements. The hash source decides the tier ceiling: read from the machine allows `validated`, supplied by the vendor `community`, merely declared only a profile.',
        caps: ['machinery.manifest'],
      },
      {
        title: 'Enrol',
        body: '`assurance machinery enrol` declares the identity and seals a receipt. Re-enrolling an unchanged machine writes nothing; a changed configuration is drift and is refused as an enrolment. `assurance machinery amend-enrolment` changes only site or owner, as a new record.',
        caps: ['machinery.enrol', 'machinery.amend_enrolment'],
      },
      {
        title: 'Record each intervention',
        body: '`assurance machinery record-change` seals an intervention that names the item touched. This is the evidence of intervention the annex describes.',
        caps: ['machinery.intervention'],
      },
      {
        title: 'Join intervention to verification',
        body: '`assurance machinery coverage` marks a function stale when a verification predates an intervention on an item that implements it. Only `current` counts as cover; `unchecked`, `incomplete`, `never_verified` and `not_demonstrable` do not.',
        caps: ['machinery.coverage'],
      },
      {
        title: 'Check the Declaration against the machine',
        body: '`assurance fleet declare` binds a Declaration of Conformity to a configuration hash, and `assurance fleet declaration` checks whether it still describes the machine.',
        caps: ['fleet.declare', 'fleet.declaration'],
      },
      {
        title: 'Seal a passport',
        body: '`assurance machinery passport` seals the position and `assurance machinery check` re-verifies a passport you did not produce. Exit 3 means covered only on evidence whose provenance the filer declared.',
        caps: ['machinery.passport', 'machinery.passport_check'],
      },
    ],
    youGet: [
      'You get an enrolment receipt, a dated list of interventions, per-function coverage with the verification and intervention that decided it, and a passport. The staleness report names the function, the last verifying bundle, the intervention that invalidated it and the days since.',
      'An auditor or insurer re-checks the passport without an account, because the check is a domain function open to anyone. A passport check shows the passport matches the records it names; it does not show the records are true.',
    ],
    notEstablished: [
      'That the machine is safe, that the manifest is complete, or that the declared serial is the physical unit in front of anyone.',
      'That an intervention record is accurate. It is the filer’s account of what was touched, bounded by the ledger’s own clock.',
      'That a conformity assessment has been done or passed, or that a Declaration of Conformity is valid. This product does not perform or replace either.',
      'That items without a hash have not changed. They are reported uncomparable, never unchanged.',
    ],
    whoActs: [
      'The obligation sits with the manufacturer, and for the operational record with whoever maintains the machine. The product feature is the record: manifest, intervention seal, coverage join and passport. The human decisions are the enrolment declaration, who counts as the technician, what a verification declares it covers, and whether the Declaration of Conformity is reissued. Conformity assessment and the CE decision are not software acts here.',
    ],
    statusNote:
      'Enrolment, intervention sealing and the passport have CLI and HTTP routes; they have no MCP tool, by design, because they are declarations by a named person. Coverage, diff and the passport check are readable over MCP.',
    statusCaps: [
      'machinery.enrol',
      'machinery.amend_enrolment',
      'machinery.manifest',
      'machinery.intervention',
      'machinery.coverage',
      'machinery.passport',
      'machinery.passport_check',
      'fleet.declaration',
    ],
    related: ['machine-safety-verification', 'continuous-machine-assurance', 'cra-article-14', 'evidence-attestation'],
    docs: [
      { label: 'Machinery Annex III guide', href: '/docs/assurance/machinery' },
      { label: 'Manufacturer view', href: '/solutions/manufacturer' },
      { label: 'Plant operator view', href: '/solutions/plant-operator' },
    ],
    faq: [
      {
        q: 'When does Annex III 1.1.9 apply?',
        a: 'The Machinery Regulation applies from 20 January 2027. The annex requires a machine to identify the software it needs to operate safely and to collect evidence of intervention in, or modification of, that software or its configuration.',
      },
      {
        q: 'What counts as an intervention record?',
        a: 'A sealed record naming the person, the date and the manifest item that was touched. The item link is what lets the coverage join date a verification as no longer applying.',
      },
      {
        q: 'Does a covered passport mean the machine complies?',
        a: 'No. It means every declared function has a current verification on recorded evidence. It does not decide conformity or safety.',
      },
      {
        q: 'What if the firmware changed but the version string did not?',
        a: 'The diff reports it. A hash moving on an item that implements a safety function is graded as safety-relevant drift even with an unchanged version label.',
      },
    ],
  },
  // ---------------------------------------------------------------------------------------------
  {
    slug: 'machine-safety-verification',
    name: 'Machine safety verification',
    intent: 'Declared envelope versus recorded run, tiers and what validated requires',
    title: 'Machine safety verification: envelope, tiers, recorders',
    description:
      'Checking a recorded run against a declared safety envelope, why most results cap at community, and what a recorder attestation needs for validated.',
    kicker: 'Verification',
    h1: 'Machine safety verification: a recorded run against a declared envelope, with a tier that cannot be asserted',
    definition:
      'Machine safety verification checks that a recorded run of a machine stayed inside the limits its operator declared, and attaches an evidence tier that is computed from the weakest input rather than supplied by the caller.',
    problem: [
      'A collaborative cell is only as safe as the margins it was assessed against: a protective separation distance, a speed limit, a stopping distance. A sign-off that says those margins were met has to say on what evidence, and a number typed into a spreadsheet is weaker evidence than a measured trace from a recorder.',
      'If a caller could pass in the evidence level, it would be passed in. The verification engine therefore computes the tier as the floor of every input the verdict rests on: the trace provenance, the stopping and sensing figures, and the body-region limits table.',
    ],
    workflow: [
      {
        title: 'Declare the envelope',
        body: 'The envelope states reaction and stopping times, sensing figures and limits. `assurance machine separation` and `POST /v1/machine/separation` show the protective separation distance term by term from `S = Sh + Sr + Ss + C + Zd + Zr`.',
        caps: ['machine.separation'],
      },
      {
        title: 'Verify a recorded run',
        body: '`assurance machine verify` checks the trace against the envelope. Each check ends verified, violated, unchecked or not applicable. `unchecked` is a first-class outcome, and a run that left a check unchecked is never reported as a pass.',
        caps: ['machine.verify'],
      },
      {
        title: 'Read the tier',
        body: 'A simulated trace caps at `community`. A trace whose provenance only the filer declared also caps at `community` and may not claim physical behaviour. A datasheet figure caps at a profile. `validated` needs measured figures plus provenance that something other than the filer vouches for.',
      },
      {
        title: 'Attest the recorder',
        body: '`assurance machine recorder-sign` produces a signed attestation binding exact trace bytes to a recorder key and a machine reference. The verifier adds the recorder’s public key to its own trust file with `assurance machine recorder-trust`; the filer cannot supply that list.',
        caps: ['machine.recorder_sign', 'machine.recorder_trust'],
      },
      {
        title: 'Re-check the bundle',
        body: '`assurance machine check` and `POST /v1/machine/bundle/check` re-check a sealed bundle. With the original envelope and trace they re-run the engine and report `reproduced`; without them the result is integrity only and says so.',
        caps: ['machine.check'],
      },
      {
        title: 'Feed the staleness join',
        body: 'A verification is dated by when the run happened. A later intervention on an item that implements the function makes it stale, which `assurance machinery coverage` reports.',
        caps: ['machinery.coverage'],
      },
    ],
    youGet: [
      'You get a sealed verification bundle: the check outcomes, the verdict, the tier with the reason for it, the stated limitations and the engine version. The checker is open to anyone, because the people who most need to check a bundle, such as an insurer or a notified body, should not need an account.',
      'A recorder attestation is a statement by the holder of an Ed25519 key that exact trace bytes belong to a named recorder and machine reference. It is accepted only under the verifier’s own trust list, and a revoked key returns the claim to the lower tier.',
    ],
    notEstablished: [
      'That the formula is the standard’s text. The repository holds no copy of ISO/TS 15066 or ISO 13855, so the constants and the intrusion distance are unverified here.',
      'That sample values are true physical measurements, that a recorder was calibrated or installed correctly, or that the machine reference is the machine in front of anyone. Cryptographic integrity is not recorder authenticity, and neither is physical safety.',
      'That the reaction and stop times are re-measured. They are taken from the envelope.',
      'That an accepted attestation is sufficient for the higher tier. It is necessary and never sufficient.',
    ],
    whoActs: [
      'Software computes the checks and the tier. People declare the envelope, choose which recorder keys the verifier trusts, supply measured figures and decide what to do with a violated or unchecked result. Adding a key to a trust list is the verifier vouching for its holder; key custody has no HTTP route or MCP tool, by design.',
    ],
    statusNote:
      'Verification and the bundle check are available on the CLI, HTTP API and MCP. Recorder signing and trust tooling are CLI-only, by design. Hosted validated verification needs a recorder trust file that no deployment has today, so hosted results stay at community.',
    statusCaps: [
      'machine.separation',
      'machine.verify',
      'machine.check',
      'machine.recorder_sign',
      'machine.recorder_trust',
      'attest.trust_list_add',
      'attest.trust_list_revoke',
    ],
    related: ['machinery-regulation-evidence', 'evidence-attestation', 'continuous-machine-assurance', 'offline-assurance-kit'],
    docs: [
      { label: 'Machine safety guide', href: '/docs/assurance/machine' },
      { label: 'Key ceremony', href: '/docs/assurance/key-ceremony' },
    ],
    faq: [
      {
        q: 'What does the validated tier need?',
        a: 'Measured figures, and a recorder attestation accepted under a trust list the verifier holds and the filer cannot supply. That is necessary, not sufficient.',
      },
      {
        q: 'Why do most results read community?',
        a: 'Provenance a filer only declares is recorded but not believed, so a file that says field data is indistinguishable from one produced on a laptop.',
      },
      {
        q: 'What does unchecked mean?',
        a: 'The run did not exercise a check, so nothing was shown and nothing failed. It is reported as such, not as a pass.',
      },
      {
        q: 'Can I pass a tier in?',
        a: 'No. The tier is computed and a bundle claiming one it cannot support is rejected on re-check.',
      },
    ],
  },
  // ---------------------------------------------------------------------------------------------
  {
    slug: 'evidence-attestation',
    name: 'Evidence attestation',
    intent: 'Counter-signed ledger heads, anchors and what a signature does and does not prove',
    title: 'Evidence attestation: signed heads and key custody',
    description:
      'Counter-signed ledger heads, local signing, anchored exports and a prepared-not-performed key ceremony. What a signature proves, and what it does not.',
    kicker: 'Attestation',
    h1: 'Evidence attestation: signed ledger heads, anchors and what a signature proves',
    definition:
      'Evidence attestation is a digital signature over a ledger’s length and head, made at a stated time by a key the ledger’s holder does not control, so that a later rewind contradicts a statement that already exists.',
    problem: [
      'A hash chain exposes edits but not removal, so something must leave the building that depends on the whole history and is signed by someone else. The attestation guide describes two deployments for two kinds of reader: a signer under the operator’s own control, and a service counter-signature for a manufacturer that does not want a second host.',
      'The second depends on a service key. The key-ceremony guide states its status flatly: prepared, not performed. No production key exists, no deployment has either trust variable, and nothing in the guide has been done by the assistant or by CI.',
    ],
    workflow: [
      {
        title: 'Make a key away from the ledger',
        body: '`assurance attest keygen` writes an Ed25519 pair, refuses to overwrite either file, creates the private file with owner-only permissions and refuses to place it beside the ledger. A key stored beside the records it signs is decoration.',
        caps: ['attest.keygen'],
      },
      {
        title: 'Sign on a timer',
        body: '`assurance attest sign` attests the current head. The exit code is the interface: 0 signed, 1 a finding such as a rewind, a fork or an unexpected key, 2 could not run, 3 the log ends in an unfinished write.',
        caps: ['attest.sign'],
      },
      {
        title: 'Counter-sign without sending the ledger',
        body: '`POST /v1/ledger/attest` takes three numbers computed by the holder. The service signs them and refuses a shorter ledger with 409. Every such attestation carries `declared_by_holder` inside the signed bytes; operator signing from the ledger carries `read_from_ledger`. With no service key configured the route answers 503 `no_attestation_key_configured`.',
        caps: ['attest.sign', 'attest.service_key'],
      },
      {
        title: 'Verify without an account',
        body: '`assurance attest verify` and `POST /v1/ledger/attest/verify` check a log under a public key. The key must be confirmed by a route other than the one the attestations travelled on; reading sixteen hex characters aloud over a telephone is a sufficient method.',
        caps: ['attest.verify', 'attest.log'],
      },
      {
        title: 'Anchor an export',
        body: 'A hosted export embeds an anchor only from an operator-signed `read_from_ledger` record. `assurance attest anchor-all` counter-signs hosted tenant ledgers on a timer.',
        caps: ['attest.anchor_all'],
      },
      {
        title: 'Rehearse and preflight the ceremony',
        body: '`assurance attest preflight` reports whether counter-signing and validated verification would work on this host and lists what it did not check. The rehearsal tests run the ceremony on throwaway keys. `assurance attest trust-list` manages recorder public keys.',
        caps: ['attest.preflight', 'attest.trust_list_create', 'attest.trust_list_verify'],
      },
    ],
    youGet: [
      'You get an attestation log, an append-only record that chains to itself, which both parties can hold. The signed bytes include the basis, so a declared head is never mistaken for one read from the ledger, and the note field is marked as the requester’s own text.',
      'The account holder’s own administrator cannot rewind without contradicting a signature by a key nobody there holds, and the service cannot fabricate evidence it never saw. Both statements assume the signer’s copy of the log is kept.',
    ],
    notEstablished: [
      'That the public key belongs to whom you think. A signature is worth exactly the provenance of the key.',
      'That records appended since the last attestation are intact.',
      'That the records were true when written. Attestation is about custody, not content.',
      'That a service-held anchor is strong. Where the service holds the ledger, the log and the key, the anchor protects only an account holder who keeps their own copy of a signed head.',
      'That hardware-token or KMS signing is supported. The key-ceremony guide says it is not today.',
    ],
    whoActs: [
      'Software signs on a timer and verifies. Key custody, rotation, revocation and the decision to trust a recorder key are people’s decisions, recorded in the ceremony’s decision record. Key tooling has no HTTP route and no MCP tool, by design: key custody and verifier trust are not an agent’s or a request’s to change.',
    ],
    statusNote:
      'Signing and verifying are available. The hosted counter-signature needs a service key that is not configured on any deployment today. The ceremony is documented and rehearsed on throwaway keys; it has not been performed.',
    statusCaps: [
      'attest.keygen',
      'attest.sign',
      'attest.verify',
      'attest.log',
      'attest.service_key',
      'attest.anchor_all',
      'attest.preflight',
      'attest.trust_list_add',
    ],
    related: ['machine-evidence-ledger', 'machine-safety-verification', 'offline-assurance-kit', 'assurance-api-and-mcp'],
    docs: [
      { label: 'Attestation guide', href: '/docs/assurance/attest' },
      { label: 'Key ceremony', href: '/docs/assurance/key-ceremony' },
      { label: 'Trust runbook', href: '/docs/assurance/trust-runbook' },
    ],
    faq: [
      {
        q: 'What does a counter-signature prove?',
        a: 'That a head with a stated length existed at a stated time and that someone without the key could not have produced the signature. It does not show the contents are true or who wrote them.',
      },
      {
        q: 'Has the key ceremony been done?',
        a: 'No. It is prepared and rehearsed on throwaway keys. No production key exists.',
      },
      {
        q: 'Can I verify an attestation without an account?',
        a: 'Yes. The verification route needs no key and no account, because the readers are regulators and insurers.',
      },
      {
        q: 'What happens if the ledger got shorter?',
        a: 'Signing refuses it as a finding. An append-only ledger does not get shorter, so the local signer exits 1 and the service answers 409.',
      },
    ],
  },
  // ---------------------------------------------------------------------------------------------
  {
    slug: 'offline-assurance-kit',
    name: 'Offline assurance kit',
    intent: 'An enrolment kit that runs inside the plant behind a guard that records network attempts',
    title: 'Offline assurance kit: enrol machines on-site',
    description:
      'A kit that enrols machines on the plant side and writes your own ledger and report, behind a guard that refuses and records outbound attempts it can see.',
    kicker: 'Offline kit',
    h1: 'The offline assurance kit: a ledger on your disk and a guard that records any attempt to reach out',
    definition:
      'The offline assurance kit is a runnable folder that enrols machines from exported files into a ledger on the plant’s own disk, with no account, no upload and a guard over the process’s network layer.',
    problem: [
      'A tool that runs inside a plant has to get past the plant’s network and IT review. Vendors routinely say that it works offline and nothing leaves the network, and plant IT cannot check that statement.',
      'The kit answers with a record instead of a promise. It arms a guard over the process’s socket layer and process creation, refuses and records any outbound attempt it can see with the line of code that made it, and seals that record into the account holder’s own ledger. The guard runs inside the process it watches, so a network namespace is what enforces the boundary at the operating-system level.',
    ],
    workflow: [
      {
        title: 'Write the kit',
        body: '`assurance kit init plant/` writes a runnable kit. Edit `kit.json` and the collection plan, drop the exports in a folder, and the kit refuses to run while template values such as a placeholder manufacturer remain.',
        caps: ['kit.init'],
      },
      {
        title: 'Show what it would touch',
        body: '`assurance kit check plant/kit.json` lists every file the run would open, names plan items that match no file and every remaining placeholder, and writes nothing. It is the command to put in front of whoever approves the tool.',
        caps: ['kit.check'],
      },
      {
        title: 'Run it',
        body: '`assurance kit run plant/kit.json --out plant/out` enrols every machine. Exit 0 means every machine was enrolled and nothing tried to reach the network; 1 is a finding, including a refused connection attempt; 2 is a run that could not happen.',
        caps: ['kit.run'],
      },
      {
        title: 'Read what it wrote',
        body: 'The output is an HTML report, the evidence ledger, a run record and an attestation request holding three numbers and a note. The report prints the guard’s limits and a numbered list of what one run does not establish.',
      },
      {
        title: 'Keep going offline',
        body: 'The ledger is an ordinary evidence ledger. `assurance machine verify`, `assurance machinery record-change` and `assurance machinery coverage` append to or read it, and `assurance attest verify --ledger` checks a counter-signed head later.',
        caps: ['machine.verify', 'machinery.coverage'],
      },
    ],
    youGet: [
      'You get a sealed ledger on your own disk, a report, a run record and an attestation request that can later be counter-signed. Because the guard’s record is sealed into the same ledger, “did this tool send anything anywhere” has an answer with a hash on it, in a file you hold.',
      'The claim is enforced, not asserted. The repository’s airgap test suite injects a subprocess and a datagram into the kit and checks the import closure and a real run from the outside; the guard has three layers, covering socket functions, an audit hook and process creation.',
    ],
    notEstablished: [
      'That nothing escaped by a route the guard cannot see. It does not cover native code that reaches the kernel without going through CPython, or data sent on a socket already connected before the guard began.',
      'That the guard contains a hostile process. It records intent; for an enforced boundary the guide says to run the kit in a network namespace with no interface, or behind the plant’s firewall. The CI wiring for that has been observed only on a development machine, not yet on a hosted runner.',
      'That manifests came from the machine. Exports are labelled `supplied_by_vendor` with a community tier ceiling unless the operator asserts `read_from_machine`, and that assertion is the operator’s, which software cannot check.',
      'That any advisory was matched, any physical behaviour verified, or the head signed. The report lists each as not established.',
    ],
    whoActs: [
      'The kit is for a plant engineer, an integrator or an operator who needs their own record, independent of the manufacturer’s bookkeeping, without procurement. Software collects and seals. People edit the configuration, state who prepared it, decide whether to assert read-from-machine, and choose whether to ask for a counter-signature.',
    ],
    statusNote:
      'The three kit verbs are CLI-only, by design: the kit runs on the plant’s machine and has no HTTP route or MCP tool. The hosted counter-signature that the attestation request is meant for needs a service key that is not configured today.',
    statusCaps: ['kit.init', 'kit.check', 'kit.run', 'collect.check_plan', 'collect.probe', 'attest.verify'],
    related: ['machine-evidence-ledger', 'evidence-attestation', 'continuous-machine-assurance', 'enterprise-integration'],
    docs: [
      { label: 'Offline kit guide', href: '/docs/assurance/kit' },
      { label: 'Getting started', href: '/docs/getting-started' },
      { label: 'Plant operator view', href: '/solutions/plant-operator' },
    ],
    faq: [
      {
        q: 'Can the kit be shown not to reach the network?',
        a: 'A guard refuses and records outbound connections, name resolution and process creation during a run, and a test suite checks it from outside. It records intent in-process, so a network namespace is the enforced boundary.',
      },
      {
        q: 'Do I need an account or an API key?',
        a: 'No. The kit runs without either, and nothing is uploaded.',
      },
      {
        q: 'Why does the report say community?',
        a: 'A folder of exported files cannot show which machine it came from, so items are labelled supplied by vendor and the tier ceiling stays at community.',
      },
      {
        q: 'What happens when a connection attempt is refused?',
        a: 'The run finishes, writes its evidence and exits 1 so that someone finds out which line tried. The refusal is not an ordinary network error and is not retried.',
      },
    ],
  },
  // ---------------------------------------------------------------------------------------------
  {
    slug: 'assurance-api-and-mcp',
    name: 'Assurance API and MCP',
    intent: 'One domain function behind the CLI, HTTP API and MCP, and what 401 and 402 mean',
    title: 'Assurance API and MCP: one function, three surfaces',
    description:
      'The CLI, the HTTP API and the MCP server call the same domain functions. How 401 and 402 differ, what MCP may and may not do, and how parity is tested.',
    kicker: 'Interfaces',
    h1: 'The assurance API and MCP server: the same domain function behind every surface',
    definition:
      'The assurance interfaces are a command line, an HTTP API and an MCP server that each call the same domain function for a given capability, so a result does not depend on which door was used.',
    problem: [
      'Three interfaces can drift into three products. An agent tool that answers differently from the CLI, or an API route that is gated differently from the page that describes it, is how copy ends up promising something the code does not do.',
      'The repository guards against that by cataloguing every capability once, with its CLI command, HTTP route and MCP tool or the reason one is absent, and by exporting that catalogue as a contract file the site renders instead of retyping.',
    ],
    workflow: [
      {
        title: 'Read the catalogue',
        body: '`assurance capabilities`, `GET /v1/capabilities` and the MCP tool `capabilities` list every capability and whether each surface offers it. `assurance capabilities --check` exits 0 when the catalogue matches the code.',
        caps: ['catalogue.capabilities'],
      },
      {
        title: 'Authenticate and get entitled',
        body: 'The API answers 401 with no or an invalid key and 402 when the key is valid but the plan lacks the capability. Entitlements are read on every request, and a revoked key stops at once. `GET /v1/plans` mirrors what the code enforces.',
        caps: ['catalogue.plans', 'account.me'],
      },
      {
        title: 'Call the same function',
        body: '`assurance machinery coverage`, `POST /v1/machinery/coverage` and the MCP tool `machinery_coverage` reach one domain function. `assurance check machine` and `POST /v1/check/machine` are the free path for one manifest and one advisory.',
        caps: ['machinery.coverage', 'check.machine', 'check.services'],
      },
      {
        title: 'Use MCP for reads and bounded work',
        body: 'The MCP server wraps the real HTTP API; with no deployment configured, every tool returns the same not-configured error. Most tools read or verify. A few do case work for a named person’s account: `change_claim`, `change_advance`, `change_reverify`, `change_assess_drift` and `change_assess_intervention`.',
        caps: ['change.claim', 'change.advance', 'change.reverify'],
      },
      {
        title: 'Leave decisions to people',
        body: 'There is no tool to close, reject, defer or resume a case, to answer its open questions, to waive a re-verification, to establish awareness, or to change a key or a trust list. Over HTTP a decision needs a key issued to an individual operator with the decider role; an account-level key is refused with `operator_required`, and a mismatched actor with `actor_mismatch`.',
        caps: ['change.decide', 'art14.awareness'],
      },
      {
        title: 'Check parity',
        body: 'Tests build one synthetic ledger, point the CLI, API and MCP at it and compare the normalised domain fields. Another set reads the live app for gates, so a new route that touches tenant data without one fails.',
      },
    ],
    youGet: [
      'You get a contract, `public/capabilities.json`, generated from the code and rendered at /docs/capabilities, plus an OpenAPI schema generated from the app. An agent or an integration reads capabilities instead of guessing.',
      'The status model is deliberately plain: a surface is available (the command, route or tool exists in this build), by design (absent on purpose, with a stated reason) or planned (a known gap, listed so it is not hidden).',
    ],
    notEstablished: [
      'That the surfaces behave identically in every detail. The parity tests compare domain fields on read-only capabilities, not envelopes or exit codes against HTTP status codes.',
      'That anything is deployed or what any plan includes. Available describes this build only.',
      'That an MCP tool’s answer is a safety conclusion. Tools read, verify and relay; a language model never decides a safety result.',
      'That an actor name is the person. The ledger records a name as declared unless an operator key attributes it.',
    ],
    whoActs: [
      'Software answers requests under the entitlements in force. Named people decide: closing a case, an Article 14 awareness determination, key and trust changes. The agent surface is built so that an assistant can help read and prepare, and the hard stops are in the domain layer, not in a prompt.',
    ],
    statusNote:
      'The contract’s counts come from the file itself. The sole planned item on any surface is the CLI verb for the signed advisory case route; the table below shows live values for the capabilities on this page.',
    statusCaps: [
      'catalogue.capabilities',
      'catalogue.plans',
      'check.machine',
      'check.fleet_machine',
      'machinery.coverage',
      'change.claim',
      'change.decide',
      'art14.awareness',
    ],
    related: ['industrial-autonomous-assurance', 'cra-article-14', 'enterprise-integration', 'evidence-attestation'],
    docs: [
      { label: 'Capabilities by surface', href: '/docs/capabilities' },
      { label: 'Developers and API reference', href: '/developers' },
      { label: 'MCP connector', href: '/connectors/mcp' },
      { label: 'CLI', href: '/cli' },
    ],
    faq: [
      {
        q: 'What is the difference between 401 and 402?',
        a: '401 means no key or an invalid key. 402 means the key authenticated but the plan does not include the capability. The plan is read on every request.',
      },
      {
        q: 'Can an AI agent close a case?',
        a: 'No tool exists for it. Closing, rejecting, deferring and resuming are a named person’s acts on the CLI or the HTTP API.',
      },
      {
        q: 'Is the MCP server read-only?',
        a: 'Mostly. Most tools read or verify, and a few perform bounded case work. Nothing decides, closes or changes trust.',
      },
      {
        q: 'How do I know a capability exists on a surface?',
        a: 'Read the contract at /capabilities.json or the table at /docs/capabilities. It is generated from the code, and a test fails when it is stale.',
      },
    ],
  },
  // ---------------------------------------------------------------------------------------------
  {
    slug: 'enterprise-integration',
    name: 'Enterprise integration',
    intent: 'File-based inventory import, public-source ingest, ops cycle and offboarding',
    title: 'Enterprise integration: file import, ingest, offboarding',
    description:
      'What connects today: a file-based inventory importer, public-source ingest, an operator cycle and tenant export. None is a supported adapter or live connector.',
    kicker: 'Integration',
    h1: 'Enterprise integration: file-based imports and operator tooling, labelled as such',
    definition:
      'Integration here means moving data in and out through files and operator commands, with no live connector to any other system, so that each hand-over can be inspected and replayed.',
    problem: [
      'A plant that already keeps a list of its machines in an asset-management system or a spreadsheet does not want to retype it. A procurement review will also ask what the tool connects to, and a vague answer is worse than a narrow one.',
      'The honest answer is narrow. The inventory importer is a file importer: not a live CMDB connector, not an integration with SAP PM, Maximo or any other product, and not a supported adapter. The platform underneath lists a small set of adapters as an intended supported scope, and the README marks everything else as evolving.',
    ],
    workflow: [
      {
        title: 'Import an inventory file',
        body: '`assurance machinery import-inventory export.csv --mapping mapping.json` enrols rows through the one enrolment function. CSV or JSON, at most 500 rows by default, with a `--dry-run` that validates against a copy of the ledger. The worked example in the tests is a synthetic SAP-style export, a fixture and not a connection.',
        caps: ['machinery.import_inventory'],
      },
      {
        title: 'Or send canonical rows',
        body: '`POST /v1/machinery/enrol/batch` takes canonical machine objects, at most 200 per request. CSV parsing stays in the CLI on purpose, because a server that parses arbitrary uploads is a larger attack surface.',
        caps: ['machinery.import_inventory'],
      },
      {
        title: 'Ingest public advisories from files',
        body: '`assurance intel ingest` records KEV, NVD, EPSS and CSAF files you already hold. `assurance intel refresh --live --allow-host HOST` fetches CSAF from named hosts only, and is the operator’s explicit act. Tests use recorded and contract fixtures, one on a reserved invalid domain, not a live provider.',
        caps: ['intel.ingest', 'intel.refresh', 'fleet.import_csaf'],
      },
      {
        title: 'Run the operator cycle',
        body: '`assurance ops cycle` runs refresh, watch, ledger verification, anchoring, backup and backup verification, and appends one record. Example cron and systemd files are provided and marked as examples; nothing is installed by the repository.',
        caps: ['ops.cycle', 'ops.check', 'ops.status'],
      },
      {
        title: 'Report to a workspace, opt in',
        body: '`assurance watch push` reports the latest sealed run to your own hosted ledger. It is opt-in, and the guide lists what is and is not sent.',
        caps: ['watch.push'],
      },
      {
        title: 'Export and offboard',
        body: '`assurance tenant export` and `assurance tenant verify-export` produce and check a manifest-hashed export. `assurance tenant delete` prints a plan; with `--execute` it needs a verified export that matches the ledger now, a repeated account id and a named actor.',
        caps: ['tenant.export', 'tenant.verify_export', 'tenant.delete'],
      },
    ],
    youGet: [
      'You get per-row outcomes (enrolled, already enrolled, configuration differs, identity conflict, rejected with a reason), a sealed import record holding file and mapping hashes, and counts. One bad row never aborts the batch, and rows past the limit are reported, never dropped silently.',
      'For offboarding you get an export with a manifest and a verification note a third party can follow with standard tools, and a tombstone in the operator ledger that holds no record contents.',
    ],
    notEstablished: [
      'That an inventory file is complete or accurate. It is as declared by the source system, nothing was read from a machine, and an item missing from the file is missing from the record.',
      'That deletion removes every copy. Backups, replicas, exports and the account holder’s own copies are outside what the tool removes, and unlinked files are not overwritten.',
      'That any connector is supported. A file importer is not an adapter, and in the platform layer the REST adapter is a tested library that no shipped loader registers (no deployment uses it unless an operator wires it in), while the other adapter modules are canned stand-ins that refuse to run unless a test opts in.',
      'That a live public-source fetch was exercised by the tests. The one networked step is not covered by the end-to-end pipeline test.',
    ],
    whoActs: [
      'Software validates, imports, ingests, backs up and verifies. A person names the actor on an import, chooses the allowed hosts for a fetch, decides retention (the product deletes nothing automatically), closes the billing account before offboarding and carries out any deletion. Tenant operations are operator tooling: no HTTP route and no MCP tool.',
    ],
    statusNote:
      'Every connector on this page is evolving and file-based. The CLI carries the importers and operator tooling; the batch enrolment route exists on HTTP. Tenant tooling and the cycle have no HTTP route or MCP tool, by design.',
    statusCaps: [
      'machinery.import_inventory',
      'intel.ingest',
      'intel.refresh',
      'fleet.import_csaf',
      'ops.cycle',
      'watch.push',
      'tenant.export',
      'tenant.delete',
    ],
    related: ['supplier-advisory-fleet-impact', 'machine-evidence-ledger', 'continuous-machine-assurance', 'assurance-api-and-mcp'],
    docs: [
      { label: 'Platform status', href: '/docs/platform' },
      { label: 'Contact', href: '/contact' },
    ],
    faq: [
      {
        q: 'Is there a SAP or Maximo connector?',
        a: 'No. There is a file importer with a mapping file, and its example is a synthetic export. Nothing talks to another system.',
      },
      {
        q: 'Which adapters are supported?',
        a: 'Treat anything the README does not mark Supported as evolving. A small set of adapters is the intended supported scope, not yet claimed.',
      },
      {
        q: 'What happens to a row that cannot be enrolled?',
        a: 'It is reported with a reason and nothing is written for it. A spreadsheet-style cell starting with an equals sign or similar is kept as text and never evaluated.',
      },
      {
        q: 'Can offboarding be undone?',
        a: 'Deletion unlinks the planned files and records a tombstone. Restoring needs a backup or the verified export, which the operator keeps.',
      },
    ],
  },
];

export function getProductPage(slug: string): ProductPage | undefined {
  return PRODUCT_PAGES.find((p) => p.slug === slug);
}

/** The category page, linked from every other product page and from the menus. */
export const CATEGORY_SLUG = 'industrial-autonomous-assurance';
