import { HOSTED_API } from './hostedApi';
import { productHref } from './productPages';
import { QUICKSTART, SALES } from './links';

// The one path from reading about the product to using it, shared by the home page (short form) and
// /start (long form). Every state below is something the code or docs/GO-LIVE.md and
// docs/claims-registry.md say today; none is a plan. A state is one of:
//   live     - exists and works as described
//   offline  - runs on the visitor's own machine; nothing leaves it
//   hosted   - needs a deployed API; this site's build has none unless NEXT_PUBLIC_ASSURANCE_API_URL is set
//   request  - not self-serve; it goes through a conversation with NeuralBridge
//   none     - not available
export type StepState = 'live' | 'offline' | 'hosted' | 'request' | 'none';

export interface StepTag {
  state: StepState;
  label: string;
}

export interface JourneyStep {
  id: string;
  title: string;
  /** One or two sentences for the home page. */
  short: string;
  /** The full text for /start. */
  detail: string[];
  tags: StepTag[];
  links: { label: string; href: string }[];
  /** A command block for /start, when the step is something you run. */
  code?: string;
}

export const TAG_CLASS: Record<StepState, string> = {
  live: 'is-live',
  offline: 'is-offline',
  hosted: 'is-gap',
  request: 'is-gap',
  none: 'is-none',
};

const hostedTag: StepTag = HOSTED_API
  ? { state: 'hosted', label: 'Hosted: this site is connected to an API' }
  : { state: 'none', label: 'Hosted: no public API deployed' };

export function journeySteps(): JourneyStep[] {
  return [
    {
      id: 'understand',
      title: '1. Visitor: understand what it does and does not do',
      short:
        'One page per question, each stating what it does not establish and who decides. Start with the product overview, or the page for your role.',
      detail: [
        'Industrial Autonomous Assurance records what software and configuration is on each machine, which verification covered which configuration, and when that stopped being true. It drafts; named people decide. It does not make anyone compliant, certified or safe.',
        'You bring: a list of your machines, the safety software on each, and any verification records. You get back: a sealed manifest per machine, a coverage report, change-assurance cases, and a passport or export that anyone can re-check. The role pages say what the problem looks like from your seat.',
      ],
      tags: [{ state: 'live', label: 'Live: read it now' }],
      links: [
        { label: 'Product overview', href: productHref('industrial-autonomous-assurance') },
        { label: 'Your role', href: '/#roles' },
        { label: 'What is stored and what each record can prove', href: '/trust' },
      ],
    },
    {
      id: 'free',
      title: '2. A real demonstration: what is real today',
      short:
        'A worked synthetic report in a second, then a check of any evidence file you were handed. Both run on your own machine, with no account and no upload.',
      detail: [
        'Real: the offline commands run the actual engines, need no account, no key and no network; the kit’s guard refuses and records any network or process attempt it can see. The worked report uses synthetic machines and says so. The evidence checks read a file you name and say which facts it establishes and which it cannot.',
        HOSTED_API
          ? 'The same checks are also answered by the hosted API this site is connected to, within the daily allowances stated on the pricing section.'
          : 'Not available: the browser versions of these checks (the playgrounds on the home page and the /verify page) need a hosted API. None is deployed to a public endpoint, so those pages show the request they would send and say so. The commands below do the same work locally.',
      ],
      tags: [
        { state: 'offline', label: 'Offline: available' },
        hostedTag,
      ],
      links: [
        { label: 'Check an evidence file', href: '/verify' },
        { label: 'Offline kit guide', href: '/docs/assurance/kit' },
      ],
      code: `python -m assurance report demo --out demo/          # a worked report; synthetic machines
python -m assurance evidence verify export.json     # a ledger export you were handed
python -m assurance machine check bundle.json       # a machine verification bundle`,
    },
    {
      id: 'account',
      title: '3. Account and keys',
      short:
        'There is no self-serve sign-up or checkout. The Validator tier needs no account; the software is supplied on request and a Register or Cell key is issued after a conversation.',
      detail: [
        'The source repository is private and the code is proprietary, so this site links to no repository. A copy of the source, with the CLI and offline kit, is supplied by NeuralBridge on request through the contact page. Nothing here promises a response time.',
        'There is no self-serve sign-up and no live checkout. `POST /v1/checkout` refuses with 503 `price_not_configured` until an operator configures Stripe prices on a deployed API, and none is deployed. Prices on this site (€390 and €1,290 a month) are unvalidated list prices, not quotes.',
        'Where an account is agreed, the operator issues a key from the account store with the billing CLI; the key is shown once and only its hash is kept. A missing or invalid key is 401. A valid key on a plan without the route is 402 with the remedy named. Running the API yourself from the source copy enforces the same keys and plans.',
      ],
      tags: [
        { state: 'live', label: 'Validator: no account' },
        { state: 'request', label: 'Source copy, Register and Cell keys: by request' },
        { state: 'none', label: 'Self-serve sign-up and checkout: not available' },
      ],
      links: [
        { label: 'Ask for a copy of the source', href: `${SALES}?intent=source` },
        { label: 'Ask for an account or key', href: `${SALES}?intent=account` },
        { label: 'Plans as enforced', href: '/#pricing' },
        { label: 'Developers: auth and routes', href: '/developers' },
      ],
      code: `pip install cryptography && export PYTHONPATH=src    # run from your copy of the source
python -m assurance capabilities                     # what the CLI, API and MCP each offer`,
    },
    {
      id: 'enrol',
      title: '4. Enrolment: declare a first machine',
      short:
        'A named person declares the machine, a baseline is sealed with a receipt, and later changes are compared against it. The offline kit does this into your own ledger.',
      detail: [
        'Enrolment records who declared the machine, its site and owner, and seals its safety-software manifest as the baseline. It is never rewritten: a changed site or owner is a new, chained record.',
        'Each item in the manifest carries how its identity was established: read from the machine, supplied by the vendor, or declared. That is a ceiling on every claim about it; see the trust page. Software cannot see where a hash was read, so read-from-machine is the filer’s assertion. The declaration is the customer’s responsibility.',
      ],
      tags: [
        { state: 'offline', label: 'Offline kit: available' },
        { state: 'hosted', label: 'Hosted enrol: Cell plan, needs a deployed API' },
      ],
      links: [
        { label: 'Offline kit guide', href: '/docs/assurance/kit' },
        { label: 'Machinery Annex III engine', href: '/docs/assurance/machinery' },
        { label: 'Trust: provenance classes', href: '/trust#provenance' },
      ],
      code: `python -m assurance kit init plant/                 # a skeleton: fill in kit.json and plans/cell.json
python -m assurance kit check plant/kit.json        # lists every placeholder and every file a run would open
python -m assurance kit run plant/kit.json --out plant/out`,
    },
    {
      id: 'evidence',
      title: '5. Evidence: collect and report it',
      short:
        'Collection runs on your side. The hosted service never reaches into a machine; it records only what your own Watch reports.',
      detail: [
        'Evidence is collected by your own run (`kit run`, `collect run`, `watch run`). `watch push` reports the result to an API you operate, which labels it as reported by you, with its age and the last failed attempt. A failed or incomplete look is shown as failed, never as quiet.',
      ],
      tags: [
        { state: 'offline', label: 'Collection: your side, offline' },
        { state: 'hosted', label: 'Recording what you report: needs an API and a key' },
      ],
      links: [
        { label: 'Watch guide', href: '/docs/assurance/watch' },
        { label: 'Workspace: fleet', href: '/assurance#aw-fleet' },
      ],
    },
    {
      id: 'verify',
      title: '6. Verification: re-check the record independently',
      short:
        'Anyone can recompute a ledger export or passport without trusting NeuralBridge. Unchecked and incomplete are valid outcomes, never rounded up to a pass.',
      detail: [
        'The verifier recomputes the hash chain and says which facts it establishes and which it cannot. It runs offline from the CLI. The browser verifier on /verify and the workspace ledger panel need a deployed API.',
      ],
      tags: [
        { state: 'offline', label: 'Offline verify: available' },
        hostedTag,
      ],
      links: [
        { label: 'Verify an export', href: '/verify' },
        { label: 'Workspace: ledger verification', href: '/assurance#aw-ledger-verify' },
      ],
      code: `python -m assurance evidence verify export.json
python -m assurance machinery check passport.json --ledger register.db`,
    },
    {
      id: 'deliverable',
      title: '7. Deliverable: passport and export',
      short:
        'A passport per machine and a case export, each stating its verdict and the evidence tier it rests on. They are evidence for your review, not a certificate.',
      detail: [
        'Software assembles; people review. A decision to close a case, and every key or trust change, is a named person’s act with no AI or MCP shortcut. An export is only as complete as its chain check says.',
      ],
      tags: [
        { state: 'offline', label: 'CLI: available' },
        { state: 'hosted', label: 'Hosted passport and export: Cell plan, needs an API' },
      ],
      links: [
        { label: 'Workspace', href: '/assurance' },
        { label: 'Investigate a machine', href: '/investigate' },
        { label: 'Console', href: '/console' },
      ],
    },
    {
      id: 'paid',
      title: '8. Paid subscription or service',
      short:
        'Register and Cell are plans enforced in code; checkout is not live, so they are agreed by conversation. Services are separate, scoped by conversation, and carry no capacity, SLA or price.',
      detail: [
        'Subscriptions: Register (€390 a month) and Cell (€1,290 a month) are unvalidated list prices, not quotes, and cannot be bought on this site. Enterprise terms and any custom plan are not available; there is no enterprise offering to describe beyond the plans.',
        'Services: eight kinds of work are described on the services page. None is on sale and no delivery capacity is stated. A service engagement does not include a software entitlement, nor the reverse.',
      ],
      tags: [
        { state: 'request', label: 'Plans: by request' },
        { state: 'request', label: 'Services: general conversation only' },
        { state: 'none', label: 'Self-serve checkout: not available' },
      ],
      links: [
        { label: 'Plans as enforced', href: '/#pricing' },
        { label: 'Services catalogue', href: '/services' },
        { label: 'Contact', href: SALES },
      ],
    },
    {
      id: 'ongoing',
      title: '9. Ongoing assurance',
      short:
        'Drift checks, chain verification and backups run on your own timer; your people act on what they leave. No hosted scheduler, monitoring or response time exists.',
      detail: [
        'The operator cycle (`ops cycle`) is tooling you run on a host you control. The operations guide is prepared, not performed: nothing in it has been run against a production host. NeuralBridge does not monitor your fleet.',
      ],
      tags: [
        { state: 'offline', label: 'Operator tooling: available, self-run' },
        { state: 'none', label: 'Hosted monitoring and support: not available' },
      ],
      links: [
        { label: 'Workspace', href: '/assurance' },
        { label: 'MCP connector', href: '/connectors/mcp' },
        { label: 'Trust: what is stored where', href: '/trust' },
      ],
    },
  ];
}
