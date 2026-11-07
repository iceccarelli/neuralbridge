import { DOCS, QUICKSTART, repoLink, SALES } from './links';
import { COUNTS } from './siteCapabilities';
import { productHref } from './productPages';

export interface SolutionPage {
  slug: string;
  role: string;
  kicker: string;
  headline: string;
  lead: string;
  clockAngle: string;
  painPoints: { title: string; body: string }[];
  proof: { title: string; body: string; href: string; external?: boolean }[];
  primaryCta: { label: string; href: string; external?: boolean };
  secondaryCta: { label: string; href: string; external?: boolean };
  /** Keys into IMAGES (app/lib/images.ts). `supporting` lines up with the
   * leading `proof` entries, positionally — not every proof item has one. */
  images?: { hero: string; supporting: string[] };
}

export const SOLUTIONS: SolutionPage[] = [
  {
    slug: 'manufacturer',
    role: 'Manufacturer',
    kicker: 'For manufacturers placing machines on the EU market',
    headline: 'Your Declaration of Conformity describes the machine only as it was the day you signed it.',
    lead:
      'You shipped a machine with a Declaration of Conformity, a risk assessment, and a CE mark. Every firmware patch, scanner re-zone, or PLC change since then is a day that Declaration may have stopped describing the machine — and nothing in your process says so.',
    clockAngle:
      'CRA Art. 14 puts a 24-hour early-warning clock on a manufacturer from the moment it becomes aware that a vulnerability in its product is actively exploited — even for products placed on the market before 11 Dec 2027 (Art. 69(3)). Machinery Reg. Annex III 1.1.9 requires the machine to identify the software it needs to operate safely and to collect evidence of intervention in, or modification of, that software or its configuration, applying 20 Jan 2027.',
    painPoints: [
      { title: 'The paperwork drifts silently', body: 'A configuration change nobody logged against the Declaration is the normal case, not the exception — and it is invisible until an auditor, insurer, or regulator asks.' },
      { title: 'A supplier advisory names your components, not your machines', body: 'Matching a CVE or safety advisory to which serial numbers actually run the affected firmware is manual, error-prone, and usually skipped.' },
      { title: 'You need evidence, not a promise', body: 'A Declaration bound to a configuration hash can be shown to have stopped describing the machine — on a date, not an argument.' },
    ],
    proof: [
      { title: 'Declarations bound to a configuration hash', body: 'The Cell tier binds a Declaration of Conformity to a configuration hash, so drift becomes a checkable date.', href: `/docs/assurance/fleet` },
      { title: 'Fleet advisory fan-out', body: 'One supplier advisory matched against every enrolled serial by hash, then version, then name — never version-range arithmetic.', href: `/docs/assurance/fleet` },
      { title: 'A signed supplier advisory can open a case', body: 'An advisory in a feed signed under a key your account pinned can open a change-assurance case without a named person; unsigned content cannot. Closing the case stays a named person’s decision.', href: `/docs/assurance/change` },
      { title: 'The workflow for Annex III 1.1.9 evidence', body: 'Identify the safety-relevant software, record each intervention, and see which verifications it made stale, step by step.', href: productHref('machinery-regulation-evidence') },
      { title: 'Advisories and fleet impact', body: 'How a supplier advisory is matched to enrolled machines by hash, and why a vendor advisory describes a product, not what you installed.', href: productHref('supplier-advisory-fleet-impact') },
    ],
    primaryCta: { label: 'Try the free Validator', href: '/#products' },
    secondaryCta: { label: 'Contact NeuralBridge', href: SALES },
    images: { hero: 'solution-manufacturer-hero', supporting: ['solution-manufacturer-drift', 'solution-manufacturer-fanout'] },
  },
  {
    slug: 'system-integrator',
    role: 'System integrator',
    kicker: 'For the team that commissions and changes safety software on site',
    headline: 'Every change you make on site is one the customer, and later an auditor, may ask you to evidence.',
    lead:
      'You commission cells, patch safety programs and re-zone scanners, often under a service ticket. The record of what you changed, against which baseline, and whether the earlier verification still stands tends to live on a laptop and in an email thread.',
    clockAngle:
      'Machinery Reg. Annex III 1.1.9 requires the machine to identify the software it needs to operate safely and to collect evidence of intervention in, or modification of, that software or its configuration, applying 20 Jan 2027. The manufacturer and the operator may each look to whoever made the change for that record. Nothing here makes an intervention compliant; it makes it recorded, dated and checkable.',
    painPoints: [
      { title: 'The change is yours; the question is theirs', body: 'An intervention on a safety-bearing item is easy to make and easy to forget to write down in a form the operator or the manufacturer can later check.' },
      { title: 'Your change can end the coverage of an earlier verification', body: 'A verification covers one configuration. After a recorded change, the safety functions whose last verification predates it are listed, dated, rather than assumed still covered.' },
      { title: 'A record the customer cannot check is one they must take on trust', body: 'Ledger exports and machine bundles can be re-checked offline by the customer or an auditor, with no account, and they say what they cannot establish.' },
    ],
    proof: [
      { title: 'Record an intervention against a baseline', body: 'Seal an intervention record and a new manifest; the divergence from the declared baseline is listed item by item, not summarised as pass or fail.', href: productHref('continuous-machine-assurance') },
      { title: 'See which verifications a change made stale', body: 'The staleness join names the safety functions whose last recorded verification is older than the change, and the tier each stands at.', href: productHref('machinery-regulation-evidence') },
      { title: 'Collect without false drift alarms', body: 'Vendor tools stamp volatile headers into their own exports. The collect commands find those before they produce a year of false drift.', href: `/docs/assurance/collect` },
      { title: 'Into the customer’s own ledger, offline', body: 'The offline kit writes to a ledger on the customer’s disk and refuses every outbound connection during a run. You do not host their evidence.', href: `/docs/assurance/kit` },
      { title: 'A recorder attestation, accepted only under their keys', body: 'A trace can be signed by a recorder key; the verifier accepts it only under a trust list they hold. Without one it is a claim, not a validation.', href: `/docs/assurance/machine` },
    ],
    primaryCta: { label: 'Run the offline kit', href: QUICKSTART },
    secondaryCta: { label: 'Ask about services', href: '/services' },
  },
  {
    slug: 'plant-operator',
    role: 'Plant operator',
    kicker: 'For teams running the machines, not building them',
    headline: 'You did not change the firmware. You will still be asked to explain what did.',
    lead:
      'A safety controller update, a re-zoned scanner, a PLC project patch — often pushed by an integrator or a remote service call you were not in the room for. When something goes wrong, the plant is where the questions land first.',
    clockAngle:
      'Machinery Reg. Annex III 1.1.9 requires the machine to identify the software it needs to operate safely and to collect evidence of intervention in, or modification of, it or its configuration — applying 20 Jan 2027. If your integrator or OEM can’t produce that evidence, you may be the one asked to explain it.',
    painPoints: [
      { title: 'You inherit somebody else’s change', body: 'Interventions on safety-bearing items happen without your sign-off, and nothing re-runs the verification that used to cover them.' },
      { title: '"It still works" is not evidence', body: 'A machine running fine today says nothing about whether a recorded verification still stands behind each of its safety functions.' },
      { title: 'You need your own record, independent of the OEM', body: 'The offline enrolment kit runs on your machine, into your own ledger — you do not have to trust anyone else’s bookkeeping.' },
    ],
    proof: [
      { title: 'The staleness join', body: 'A sign-off from February, a firmware change in March, and the named safety functions whose evidence stopped applying — dated, not argued.', href: `/docs/assurance/machinery` },
      { title: 'Offline enrolment kit', body: 'Your ledger, your disk. No account, no upload, and a guard that refuses every outbound socket during a run.', href: `/docs/assurance/kit` },
      { title: 'Enrolment you can amend, not rewrite', body: 'A named person declares a machine’s identity and a baseline is sealed with a receipt. A changed site or owner is a new, chained record; the original is never rewritten.', href: `/docs/assurance/machinery` },
      { title: 'The cycle from enrolment to passport', body: 'Enrol, seal a manifest, verify, detect change, find stale evidence, re-verify and record the intervention.', href: productHref('continuous-machine-assurance') },
      { title: 'What the offline kit does and does not do', body: 'Who it is for, what the socket guard records, and the limits it states about itself.', href: productHref('offline-assurance-kit') },
    ],
    primaryCta: { label: 'Run the offline kit', href: QUICKSTART },
    secondaryCta: { label: 'See pricing', href: '/#pricing' },
    images: { hero: 'solution-plant-operator-hero', supporting: ['solution-plant-operator-inspector'] },
  },
  {
    slug: 'compliance-officer',
    role: 'Safety / compliance engineer',
    kicker: 'For the person who signs the filing',
    headline: 'The 24-hour clock does not pause for a spreadsheet.',
    lead:
      'CRA Article 14 gives you 24 hours from awareness of an actively exploited vulnerability to file an early warning that indicates, where applicable, the Member States where you know the product has been made available (Art. 14(2)(a)). Getting the clock right, the reasoning right, and the field-5 territory list right, under that pressure, is not a spreadsheet problem.',
    clockAngle:
      'Two clocks, both load-bearing: the 24-hour early warning under Art. 14, and the final-report clock — 14 days from a corrective or mitigating measure for a vulnerability, one calendar month from submission of the 72-hour notification for an incident. Getting either wrong is not a rounding error.',
    painPoints: [
      { title: 'Awareness is a fact, not a feeling', body: 'The reporting platform does not independently capture the awareness timestamp for vulnerabilities — everything downstream runs from a date only you can defend.' },
      { title: 'The 39-field spec has traps', body: 'A listed territory that is not an EU Member State, a field that exceeds a character limit, a required field silently absent at your stage — the free Validator flags these before you open the platform.' },
      { title: 'A hash-chained register, not a folder of PDFs', body: 'Every case, every clock, every piece of triage reasoning, in one append-only ledger that refuses to export if it does not verify.' },
    ],
    proof: [
      { title: 'The free Article 14 validator', body: 'Checks a draft submission against the platform’s 39-field specification before you open the platform — in the offline kit or the Assurance API.', href: '/#products' },
      { title: 'Both deadline clocks, computed correctly', href: '/docs/capabilities#service-art14', body: 'The Register tier tracks the 24-hour and final-report clocks together, with the reasoning that defends each filing.' },
      { title: 'Article 14 clocks, step by step', body: 'Awareness, triage reasoning and the deadline clocks, with the filing left to the manufacturer.', href: productHref('cra-article-14') },
    ],
    primaryCta: { label: 'Try the free Validator', href: '/#products' },
    secondaryCta: { label: 'See the Register plan', href: '/#pricing' },
    images: { hero: 'solution-compliance-hero', supporting: ['solution-compliance-clocks'] },
  },
  {
    slug: 'insurer-auditor',
    role: 'Insurer / auditor',
    kicker: 'For the person who has to check someone else’s evidence',
    headline: 'You should never need an account to verify a claim.',
    lead:
      'A manufacturer hands you a Declaration of Conformity, an attestation, or a safety verification bundle. Your job is to check whether it is internally consistent and still matches the machine it describes — and you should not need to buy anything to do it. A check like this shows consistency, not that the people who produced it were right.',
    clockAngle:
      'The regulations create the paper trail you are checking: CRA Art. 14 records (applies since 11 Sep 2026) and Machinery Reg. Annex III 1.1.9 evidence of intervention (applies 20 Jan 2027). Re-checking someone else’s evidence needs no account, because the audience for a piece of evidence is a regulator or an insurer, not an account holder. Declaration, evidence-bundle, passport and attestation checks are not metered. The file verifier (POST /v1/evidence/verify, and /verify on this site) allows 20 a day per address; manifest diff allows 10 a day. Register and Cell have no daily cap on either.',
    painPoints: [
      { title: 'A hash chain only proves editing was caught', body: 'A chain rebuilt from genesis after deleting inconvenient records still verifies. Counter-signed head attestation is the part that catches deletion, and you can verify a signature without an account.' },
      { title: 'A label can lie about the bytes', body: 'The firmware says 3.9.0; the supplier’s published hash for 3.9.0 does not match what is on the machine. That mismatch is a first-class, reportable finding — not silently ignored.' },
      { title: 'You need to check, not take their word for it', body: 'Declaration check, manifest diff, bundle re-check, passport check, attestation verify and the file verifier all run with no account, by design. Only the file verifier and manifest diff carry a daily allowance; the others are not metered.' },
    ],
    proof: [
      { title: 'Free to re-check, by design', body: 'Declaration check, bundle re-verification, passport check and attestation verification are not metered in code, so the buyer or auditor is never the paying customer. The file verifier and manifest diff carry small daily allowances.', href: '/#pricing' },
      { title: 'Counter-signed head attestation', body: 'A signature over the ledger head by a key the operator does not hold — the one thing that catches a ledger that was quietly shortened.', href: `/docs/assurance/attest` },
      { title: 'Completeness against a signed anchor', body: 'A ledger export checked with the signer’s public key and an attestation log can show that nothing up to the anchored head was removed (records after it are covered by no signature); without an anchor the check reports completeness as not checked, never as a pass.', href: `/docs/assurance/attest` },
      { title: 'What a signature proves and does not', body: 'Counter-signed heads, anchors and the key ceremony, which is prepared and not performed.', href: productHref('evidence-attestation') },
      { title: 'The evidence ledger', body: 'What a hash chain detects, what it cannot, and how anchors and completeness reporting address it.', href: productHref('machine-evidence-ledger') },
    ],
    primaryCta: { label: 'Verify a bundle', href: '/#products' },
    secondaryCta: { label: 'Read how attestation works', href: `/docs/assurance/attest` },
    images: { hero: 'solution-auditor-hero', supporting: ['solution-auditor-mismatch'] },
  },
  {
    slug: 'ai-ops',
    role: 'AI / ops platform team',
    kicker: 'For teams building on top of the platform layer',
    headline: 'The assurance product is built on an integration layer you can run from source.',
    lead:
      'NeuralBridge is the FastAPI backend, MCP gateway, and connection model the assurance product is built on. If your team is exposing tools to AI agents or wiring up connection state, this is the layer underneath, not a separate pitch.',
    clockAngle:
      'The compliance clocks (CRA Art. 14 since 11 Sep 2026; Machinery Reg. Annex III 1.1.9 from 20 Jan 2027) are what the assurance layer answers to. The platform layer underneath is judged by a narrower, honest standard: what is actually supported today, not the roadmap.',
    painPoints: [
      { title: 'The platform is intentionally narrow right now', body: 'A FastAPI backend, MCP tool listing and invocation, and a small adapter set (PostgreSQL, REST) whose supported scope is intended, not yet claimed — not a universal enterprise middleware claim.' },
      { title: 'One workspace, and it reads the real APIs', body: 'The separate Vite admin UI that showed fixed sample figures has been retired. The working surfaces are /assurance, /console and /ai on this site; each says which account and API origin it is reading and shows a refusal or an empty state as itself, never a made-up result. Said plainly, not glossed over.' },
      { title: 'Broad adapter coverage is evolving, not shipped', body: 'Treat anything not marked Supported in the README as evolving. That is the honest line, and it is the one this page holds too.' },
    ],
    proof: [
      { title: 'The platform status table', body: 'The README’s status table, word for word — a test compares the site’s rows with it.', href: '/#platform' },
      { title: 'MCP gateway', body: 'Tool listing and invocation for AI agents, sitting underneath the assurance API.', href: '/#platform' },
      { title: 'The assurance MCP server', body: `${COUNTS.mcp_tools} tools over the Assurance API: reads, verifications and a few case-working writes. Closing, rejecting or deferring a case, and every key or trust change, have no tool, by design.`, href: '/docs/capabilities' },
      { title: 'One function behind every surface', body: 'The CLI, the HTTP API and MCP call the same domain function; 401 and 402 mean different things.', href: productHref('assurance-api-and-mcp') },
      { title: 'File-based integration', body: 'Inventory import and public-source ingest are file based and evolving, not supported adapters.', href: productHref('enterprise-integration') },
    ],
    primaryCta: { label: 'See what is supported today', href: '/#platform' },
    secondaryCta: repoLink('#readme')
      ? { label: 'Read the README', href: repoLink('#readme') as string, external: true }
      : { label: 'Read the docs', href: DOCS },
    images: { hero: 'solution-aiops-hero', supporting: ['solution-aiops-mcp-gateway', 'solution-aiops-dashboard-unwired'] },
  },
];

export function getSolution(slug: string): SolutionPage | undefined {
  return SOLUTIONS.find((s) => s.slug === slug);
}
