// The services catalogue. Kept free of imports so tests/test_site_services.py can run it under Node.
// This is a description of work that could be scoped, not a menu and not an offer:
// NeuralBridge states no delivery capacity, SLA, certification or price. Each entry's `today` and `gap`
// were checked against public/capabilities.json (generated from src/assurance/capabilities.py),
// docs/claims-registry.md, and the engine guides under deploy/assurance/. If a capability moves from `gap` to
// `today`, move it here in the same change; tests/test_site_services.py checks the structure.

export type Availability = 'available' | 'partial' | 'gap';

export interface Service {
  id: string;
  name: string;
  /** Who it is for. */
  customer: string;
  /** The problem in one or two sentences. */
  problem: string;
  /** What the customer brings. */
  inputs: string[];
  /** Exactly what is handed over. */
  deliverables: string[];
  /** What is not part of it. */
  exclusions: string[];
  /** What it depends on that NeuralBridge does not control. */
  dependencies: string[];
  /** What stays with the customer. */
  responsibilities: string[];
  /** What anyone can check without relying on NeuralBridge. */
  verifiable: string[];
  /** Product capability that exists today, with where it runs. */
  today: string[];
  /** What would have to be built or written first. */
  gap: string[];
  availability: Availability;
}

export const SERVICES_DISCLAIMER = [
  'No delivery team, capacity, schedule, SLA, certification or price is offered or implied by this page.',
  'Software entitlements (Validator, Register, Cell) are separate from services and are not bought by a service engagement, nor the reverse.',
  'These entries describe work that could be scoped in a conversation. Nothing here is on sale, and no engagement has been delivered that this site can cite.',
];

export const SERVICES: Service[] = [
  {
    id: 'baseline-workshop',
    name: 'Baseline evidence workshop',
    customer:
      'A manufacturer, integrator or operator with one cell or line who wants to know what safety-software evidence exists today and how strong each piece is.',
    problem:
      'Nobody can say which safety software items run on the machine, which verifications are on file, or how each item’s identity was established.',
    inputs: [
      'A list of the machines in scope and the safety software items on each.',
      'Existing exports or hashes from the machines, and any vendor-supplied files.',
      'The Declaration of Conformity and the last verification records, if they exist.',
      'A named person able to declare each machine.',
    ],
    deliverables: [
      'A session-by-session working record of what was declared, and each item’s provenance class (read from the machine, supplied by the vendor, or declared).',
      'The product’s own output on the customer’s inputs: a sealed manifest per machine, the coverage report of which safety functions have a recorded verification, and the offline kit’s check listing.',
      'A list of items whose identity is only declared, and of safety functions with no recorded verification.',
    ],
    exclusions: [
      'No conformity assessment, hazard analysis, risk assessment or legal advice.',
      'No access to the customer’s machines or network; the customer reads hashes from the machine.',
      'No statement that the machine is compliant, certified or safe.',
    ],
    dependencies: [
      'A copy of the source for the offline kit, supplied by NeuralBridge.',
      'The customer’s exports from vendor tools; their volatile headers are checked with the collect commands before they cause false drift.',
    ],
    responsibilities: [
      'Declaring each machine by a named person.',
      'Reading hashes from the machine and standing behind that statement.',
      'Deciding what to do about every gap listed.',
    ],
    verifiable: [
      'The delivered ledger and report re-verify with `evidence verify` and the hash-chain check, offline, by anyone.',
      'The kit’s check listing shows every file a run would open.',
    ],
    today: [
      'Offline kit (init, check, run), manifests, coverage and the fleet report: available in the CLI, no account.',
      'Collect plan checks for vendor-export noise: available in the CLI.',
    ],
    gap: [
      'A facilitator guide and worksheets for the session. None exists; the engine guides under /docs are the reference.',
    ],
    availability: 'available',
  },
  {
    id: 'enrolment',
    name: 'Enrolment implementation',
    customer: 'An operator or manufacturer with several to hundreds of machines to bring under one ledger.',
    problem:
      'Machine identities and baselines sit in inventory exports and spreadsheets; each machine needs a declared identity and a sealed baseline.',
    inputs: [
      'An inventory export in rows the importer reads, with a mapping file.',
      'For each machine, the declared identity, site and owner, and a safety-software manifest.',
    ],
    deliverables: [
      'A configured kit (or inventory-import mapping) for the customer’s environment.',
      'An enrolment receipt per machine and the resulting ledger, with the import run recorded.',
      'The list of rows the importer refused and why.',
    ],
    exclusions: [
      'No live connector to an asset-inventory, PLM or MES system: the importer reads a file.',
      'No declaring on the customer’s behalf; an enrolment is a named person’s declaration.',
      'No changes to any machine.',
    ],
    dependencies: [
      'Inventory import is a file importer and evolving, not a supported adapter.',
      'Hosted batch enrolment (up to 200 machines per call) needs the Cell plan and a deployed API; none is public today.',
    ],
    responsibilities: [
      'Supplying accurate exports and naming who declares each machine.',
      'Amending a changed site or owner as a new record; an enrolment is never rewritten.',
    ],
    verifiable: [
      'Each receipt and the whole ledger re-verify offline.',
      '`machinery diff` shows whether a machine is still the configuration that was sealed.',
    ],
    today: [
      'Single and amend enrolment, inventory import and the offline kit: available in the CLI.',
      'Hosted enrol, batch enrol and amend routes: in the API, Cell plan, not deployed publicly.',
    ],
    gap: ['Connectors for specific inventory or PLM systems. None is built.'],
    availability: 'available',
  },
  {
    id: 'art14-workflow',
    name: 'Article 14 workflow configuration',
    customer: 'A manufacturer that must be able to evidence its CRA Article 14 process.',
    problem:
      'It is unclear who becomes aware, who triages, who may close, and how the 24-hour and final-report clocks are tracked and defended.',
    inputs: [
      'The people and roles involved, and the current vulnerability-intake process.',
      'Product and Member State records the filing needs.',
    ],
    deliverables: [
      'A mapping of the customer’s decision points (awareness, triage, availability, filing, user notification) onto the product’s commands and routes.',
      'Operator accounts with the decider role configured on a self-hosted API, or local case conventions for the CLI.',
      'A rehearsal case on synthetic data, exported and re-verified.',
    ],
    exclusions: [
      'No legal advice, and no determination of reportability or of the moment of awareness: those are named people’s decisions.',
      'No filing on the customer’s behalf; the product records and validates a draft against the platform field specification.',
      'No assurance that a filing meets the regulation.',
    ],
    dependencies: [
      'Hosted operators and per-account ledgers need a deployed API; none is public today. The CLI works locally.',
      'The field specification is a version recorded in the code; the customer checks it against the reporting platform’s current specification.',
    ],
    responsibilities: [
      'Establishing awareness and recording it as a decision.',
      'Making and defending every triage and filing decision.',
    ],
    verifiable: [
      'A case export re-verifies with `evidence verify`; the deadline clocks are computed from recorded timestamps.',
      'An awareness correction supersedes the original, which stays in the ledger.',
    ],
    today: [
      'Article 14 signal, awareness, triage, availability, measure, user notification, filing and export: CLI, API and partly MCP (the decisions have no MCP tool, by design).',
      'Operators with a decider role: API (Cell).',
    ],
    gap: ['A reviewed internal-procedure template for manufacturers. None exists.'],
    availability: 'available',
  },
  {
    id: 'advisory-fleet-impact',
    name: 'Advisory and fleet-impact integration',
    customer: 'A manufacturer, integrator or operator that receives supplier or public-source advisories and must know which machines they touch.',
    problem:
      'An advisory names a product and a version range; nobody has joined it to the serial numbers actually running the affected artefact.',
    inputs: [
      'The advisories to be handled (CSAF 2.0 or the product’s advisory format).',
      'The enrolled fleet, and any supplier public keys, obtained independently, to pin.',
    ],
    deliverables: [
      'A configured intake: translate a CSAF advisory, fan it out across the fleet, and open a case from the result.',
      'A Watch schedule configured for the customer’s kit or cron, reading the operator’s intel store with a maximum age if wanted.',
      'A written statement of the matching basis (hash, then version, then name) as it applies to the customer’s data.',
    ],
    exclusions: [
      'No monitoring of feeds on the customer’s behalf; fetching a public feed is the operator’s act.',
      'No judgement of exploitability or reportability.',
      'No scheduler is hosted: Watch runs in the customer’s kit or cron.',
    ],
    dependencies: [
      'CSAF import is inspect-only translation and evolving.',
      'An advisory in a signed feed opens a case without a named person only if signed under a key the account pinned.',
    ],
    responsibilities: [
      'Pinning supplier keys obtained through an independent channel.',
      'Deciding every case; an unknown stays unknown.',
    ],
    verifiable: [
      'Each result lists its matching basis; a case replays from the ledger alone with `change replay`.',
    ],
    today: [
      'Fleet advisory fan-out, signed-feed assessment, supplier trust (pin, rotate, revoke), CSAF import, intel ingest and Watch: available in the CLI; hosted routes in the API.',
    ],
    gap: [
      'Automatic ingestion from supplier portals or vendor mailing lists. None is built.',
      'A hosted scheduler. The hosted API does not run Watch.',
    ],
    availability: 'available',
  },
  {
    id: 'api-mcp',
    name: 'API and MCP integration',
    customer: 'A developer or platform team wiring evidence checks into their own systems or AI tooling.',
    problem:
      'Routes and tools exist, but the customer needs them called from their own systems, with the right authentication and the right limits on what an agent may do.',
    inputs: [
      'The target systems and the events that should call the product.',
      'A reachable Assurance API instance and a key; for MCP, the client to configure.',
    ],
    deliverables: [
      'Example client code and configuration against the documented routes, and an MCP client configured for the tools that exist.',
      'Contract tests run against the customer’s own instance.',
      'A short note listing what an agent can and cannot do through MCP.',
    ],
    exclusions: [
      'No connector to any named third-party system is validated.',
      'No AI-made safety decision, and no MCP tool to decide a case or change a key or trust.',
      'No hosted API is provided by this work.',
    ],
    dependencies: [
      'The HTTP API and the MCP server exist; a deployed instance is the customer’s or an operator’s.',
      'The wider platform’s adapters are evolving unless the README marks them Supported.',
    ],
    responsibilities: [
      'Operating the instance and its keys.',
      'Treating an account-level key held by an agent as unable to make decisions.',
    ],
    verifiable: [
      '`/openapi.json`, `/capabilities.json` and `python -m assurance capabilities --check` are generated from the code.',
      'The customer’s contract tests.',
    ],
    today: [
      'HTTP API, MCP server (stdio by default, calling the HTTP API) and CLI over one set of domain functions: available.',
      'An /ai control plane for connection discovery and propose-and-approve writes: available against a local PostgreSQL.',
    ],
    gap: ['A hosted API to integrate against. None is deployed publicly.', 'Validated connectors for named third-party systems.'],
    availability: 'available',
  },
  {
    id: 'onboarding-training',
    name: 'Onboarding and training',
    customer: 'A team that will operate the product and needs to be shown how, using its own machines.',
    problem: 'The engine guides are written for the reader who already knows what to look for.',
    inputs: ['The people to be trained and their roles.', 'A working install and a small set of the customer’s own machine data.'],
    deliverables: [
      'Working sessions on the customer’s own data, following the documented quickstart and the engine guides.',
      'A written list of what each role does at each step, taken from the product’s pipeline guide.',
    ],
    exclusions: [
      'No accredited course, no certificate of competence, and no assessment of trainees.',
      'No training materials beyond the documentation that exists: no curriculum or exercise set has been written.',
    ],
    dependencies: ['A working install, which needs a copy of the source.'],
    responsibilities: ['Releasing the people’s time and naming who owns each decision afterwards.'],
    verifiable: ['The quickstart commands are exercised by CI on a clean install, so anyone can re-run them.'],
    today: ['Quickstart, per-engine guides, a pipeline guide and a local buyer-journey walkthrough: published as documentation.'],
    gap: ['A curriculum, exercises and assessment. None exists.'],
    availability: 'partial',
  },
  {
    id: 'assurance-operations',
    name: 'Ongoing assurance operations',
    customer: 'An operator who wants the unattended steps run and reviewed on a regular rhythm.',
    problem:
      'Drift checks, chain verification, attestation and backups must keep running, and someone must act on what they leave for a human.',
    inputs: ['A host the customer controls, with the kit installed.', 'The ops configuration and the people who will act on findings.'],
    deliverables: [
      'The operator cycle (watch, chain verify, anchoring, backup and verify) configured on the customer’s timer, with a preflight listing what it does not check.',
      'A periodic review of the last cycle’s status and the human actions it left.',
    ],
    exclusions: [
      'No 24/7 monitoring, response time or SLA.',
      'No hosting of the customer’s evidence.',
      'No deciding of cases: closing is a named person’s decision.',
    ],
    dependencies: [
      'The operations guide is marked prepared, not performed: nothing in it has been run against a production host.',
      'Counter-signing needs a key ceremony on the customer’s own machine, which is prepared and not performed.',
    ],
    responsibilities: ['Running and securing the host and keys.', 'Acting on the human actions the cycle leaves.'],
    verifiable: [
      'Each cycle is one recorded line; `ops status` shows its age and flags a stale cycle.',
      'The ledger, its attestations and its backups re-verify offline.',
    ],
    today: ['`ops cycle`, `ops status`, `ops check`, attestation and tenant export tooling: available as operator tooling in the CLI, not a hosted feature.'],
    gap: ['Delivery capacity to run this for anyone. None exists.', 'A tested production deployment of the hosted API.'],
    availability: 'partial',
  },
];
