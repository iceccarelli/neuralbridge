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
      title: 'Understand what it does and does not do',
      short:
        'One page per question, each stating what it does not establish and who decides. Start with the product overview, or the page for your role.',
      detail: [
        'Industrial Autonomous Assurance records what software and configuration is on each machine, which verification covered which configuration, and when that stopped being true. It drafts; named people decide. It does not make anyone compliant, certified or safe.',
        'The role pages say what the problem looks like from your seat. Every product page ends with what it does not establish.',
      ],
      tags: [{ state: 'live', label: 'Read it now' }],
      links: [
        { label: 'Product overview', href: productHref('industrial-autonomous-assurance') },
        { label: 'Your role', href: '/#roles' },
        { label: 'What is stored and what each record can prove', href: '/trust' },
      ],
    },
    {
      id: 'free',
      title: 'Use the free capability that is real today',
      short:
        'A worked synthetic report in a second, then a check of any evidence file you were handed. Both run on your own machine, with no account and no upload.',
      detail: [
        'The offline commands need no account, no key and no network. The worked report uses synthetic machines. The evidence checks read a file you name and say which facts it establishes and which it cannot.',
        HOSTED_API
          ? 'The same checks are also answered by the hosted API this site is connected to, within the daily allowances stated on the pricing section.'
          : 'The browser versions of these checks (the playgrounds on the home page and the /verify page) need a hosted API. None is deployed to a public endpoint today, so those pages show the request they would send and say so. The commands below do the same work locally.',
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
      id: 'software',
      title: 'Get the software',
      short:
        'The CLI and the offline kit run from a source copy. There is no public download or package-index release; you ask for a copy.',
      detail: [
        'The source repository is private and the code is proprietary, so this site links to no repository. A copy of the source is supplied by NeuralBridge; ask through the contact page. Nothing here promises a response time.',
        'The base install is one third-party package, `cryptography`. The hosted-API extra, the MCP gateway extra and the platform extra each add their own dependencies, listed in the README install table that ships with the source.',
      ],
      tags: [{ state: 'request', label: 'On request via Contact' }],
      links: [
        { label: 'Ask for a copy of the source', href: `${SALES}?intent=source` },
        { label: 'Quickstart', href: QUICKSTART },
      ],
      code: `pip install cryptography && export PYTHONPATH=src    # run from your copy of the source
python -m assurance capabilities                     # what the CLI, API and MCP each offer`,
    },
    {
      id: 'register',
      title: 'Register, or get credentials',
      short:
        'The Validator tier needs no account. Register and Cell are sales-assisted: checkout is not live, and a key is issued after a conversation.',
      detail: [
        'There is no self-serve sign-up and no live checkout. `POST /v1/checkout` refuses with 503 `price_not_configured` until an operator configures Stripe prices on a deployed API, and none is deployed. Prices on this site (€390 and €1,290 a month) are unvalidated list prices, not quotes.',
        'Where an account is agreed, the operator issues a key from the account store; the key is shown once and only its hash is kept. A missing or invalid key is 401. A valid key on a plan without the route is 402 with the remedy named.',
        'Running the API yourself is possible from the source copy: keys and plans are enforced by the same code there.',
      ],
      tags: [
        { state: 'live', label: 'Validator: no account' },
        { state: 'request', label: 'Register / Cell: via Contact' },
        { state: 'none', label: 'Self-serve checkout: not live' },
      ],
      links: [
        { label: 'Plans as enforced', href: '/#pricing' },
        { label: 'Talk to us', href: SALES },
        { label: 'Developers: auth and routes', href: '/developers' },
      ],
    },
    {
      id: 'enrol',
      title: 'Enrol a first machine',
      short:
        'A named person declares the machine, a baseline is sealed with a receipt, and later changes are compared against it. The offline kit does this into your own ledger.',
      detail: [
        'Enrolment records who declared the machine, its site and owner, and seals its safety-software manifest as the baseline. It is never rewritten: a changed site or owner is a new, chained record.',
        'Each item in the manifest carries how its identity was established: read from the machine, supplied by the vendor, or declared. That is a ceiling on every claim about it; see the trust page. Software cannot see where a hash was read, so read-from-machine is the filer’s assertion.',
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
      id: 'workspace',
      title: 'Use the workspace',
      short:
        'The workspace, console and investigation pages read your fleet, cases and advisories from an Assurance API with your own key. They show what that API says, nothing simulated.',
      detail: [
        'These pages are clients of the Assurance API. Point them at one with a key and they show your fleet, evidence freshness, open change-assurance cases and a single machine’s history. If the API is not configured, unreachable, or your plan lacks a view, that is what they show.',
        'Closing, rejecting or deferring a case, and every key or trust change, are named-person decisions with no AI or MCP shortcut.',
      ],
      tags: [
        { state: 'hosted', label: 'Needs an API and a key' },
        hostedTag,
      ],
      links: [
        { label: 'Workspace', href: '/assurance' },
        { label: 'Investigate a machine', href: '/investigate' },
        { label: 'Console', href: '/console' },
        { label: 'MCP connector', href: '/connectors/mcp' },
      ],
    },
  ];
}
