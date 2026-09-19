import { DEPLOY_BLOB, QUICKSTART, REPO, SALES } from './links';

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
  images: { hero: string; supporting: string[] };
}

export const SOLUTIONS: SolutionPage[] = [
  {
    slug: 'manufacturer',
    role: 'Manufacturer',
    kicker: 'For manufacturers placing machines on the EU market',
    headline: 'Your Declaration of Conformity is only true the day you sign it.',
    lead:
      'You shipped a machine with a Declaration of Conformity, a risk assessment, and a CE mark. Every firmware patch, scanner re-zone, or PLC change since then is a day that Declaration has been quietly less true — and nothing in your process says so.',
    clockAngle:
      'CRA Art. 14 puts a 24-hour clock on you the moment a vulnerability in a product you placed on the market is actively exploited — even for products sold before 11 Dec 2027 (Art. 69(3)). Machinery Reg. Annex III 1.1.9 requires you to identify the safety-relevant software on the machine and record evidence of intervention, applying 20 Jan 2027.',
    painPoints: [
      { title: 'The paperwork drifts silently', body: 'A configuration change nobody logged against the Declaration is the normal case, not the exception — and it is invisible until an auditor, insurer, or regulator asks.' },
      { title: 'A supplier advisory names your components, not your machines', body: 'Matching a CVE or safety advisory to which serial numbers actually run the affected firmware is manual, error-prone, and usually skipped.' },
      { title: 'You need evidence, not a promise', body: 'A Declaration bound to a configuration hash can be shown to have stopped describing the machine — on a date, not an argument.' },
    ],
    proof: [
      { title: 'Declarations bound to a configuration hash', body: 'The Cell tier binds a Declaration of Conformity to a configuration hash, so drift becomes a checkable date.', href: `${DEPLOY_BLOB}/FLEET.md`, external: true },
      { title: 'Fleet advisory fan-out', body: 'One supplier advisory matched against every enrolled serial by hash, then version, then name — never version-range arithmetic.', href: `${DEPLOY_BLOB}/FLEET.md`, external: true },
    ],
    primaryCta: { label: 'Try the free Validator', href: '/#products' },
    secondaryCta: { label: 'Talk to sales', href: SALES, external: true },
    images: { hero: 'solution-manufacturer-hero', supporting: ['solution-manufacturer-drift', 'solution-manufacturer-fanout'] },
  },
  {
    slug: 'plant-operator',
    role: 'Plant operator',
    kicker: 'For teams running the machines, not building them',
    headline: 'You did not change the firmware. You will still be asked to explain what did.',
    lead:
      'A safety controller update, a re-zoned scanner, a PLC project patch — often pushed by an integrator or a remote service call you were not in the room for. When something goes wrong, the plant is where the questions land first.',
    clockAngle:
      'Machinery Reg. Annex III 1.1.9 requires the machine to identify its safety-relevant software and record evidence of intervention — applying 20 Jan 2027. If your integrator or OEM can’t produce that evidence, you are the one standing in front of the inspector.',
    painPoints: [
      { title: 'You inherit somebody else’s change', body: 'Interventions on safety-bearing items happen without your sign-off, and nothing re-runs the verification that used to cover them.' },
      { title: '"It still works" is not evidence', body: 'A machine running fine today says nothing about whether its safety functions still have valid evidence behind them.' },
      { title: 'You need your own record, independent of the OEM', body: 'The offline enrolment kit runs on your machine, into your own ledger — you do not have to trust anyone else’s bookkeeping.' },
    ],
    proof: [
      { title: 'The staleness join', body: 'A sign-off from February, a firmware change in March, and the named safety functions whose evidence stopped applying — dated, not argued.', href: `${DEPLOY_BLOB}/MACHINERY.md`, external: true },
      { title: 'Offline enrolment kit', body: 'Your ledger, your disk. No account, no upload, and a guard that proves nothing left your network.', href: `${DEPLOY_BLOB}/KIT.md`, external: true },
    ],
    primaryCta: { label: 'Run the offline kit', href: QUICKSTART, external: true },
    secondaryCta: { label: 'See pricing', href: '/#pricing' },
    images: { hero: 'solution-plant-operator-hero', supporting: ['solution-plant-operator-inspector'] },
  },
  {
    slug: 'compliance-officer',
    role: 'Compliance officer',
    kicker: 'For the person who signs the filing',
    headline: 'The 24-hour clock does not pause for a spreadsheet.',
    lead:
      'CRA Article 14 gives you 24 hours from awareness of an actively exploited vulnerability to file an early warning naming every Member State where the product is available. Getting the clock right, the reasoning right, and the field-5 territory list right, under that pressure, is not a spreadsheet problem.',
    clockAngle:
      'Two clocks, both load-bearing: the 24-hour early warning under Art. 14, and the final-report clock — 14 days from a corrective or mitigating measure for a vulnerability, one calendar month from submission of the 72-hour notification for an incident. Getting either wrong is not a rounding error.',
    painPoints: [
      { title: 'Awareness is a fact, not a feeling', body: 'The reporting platform does not independently capture the awareness timestamp for vulnerabilities — everything downstream runs from a date only you can defend.' },
      { title: 'The 39-field spec has traps', body: 'A listed territory that is not an EU Member State, a field that exceeds a character limit, a required field silently absent at your stage — the free Validator catches these before you open the platform.' },
      { title: 'A hash-chained register, not a folder of PDFs', body: 'Every case, every clock, every piece of triage reasoning, in one append-only ledger that refuses to export if it does not verify.' },
    ],
    proof: [
      { title: 'The free Article 14 validator', body: 'Checks a draft submission against the platform’s 39-field specification before you open the platform — free, no account, forever.', href: '/#products' },
      { title: 'Both deadline clocks, computed correctly', href: `${DEPLOY_BLOB}/README.md`, external: true, body: 'The Register tier tracks the 24-hour and final-report clocks together, with the reasoning that defends each filing.' },
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
      'A manufacturer hands you a Declaration of Conformity, an attestation, or a safety verification bundle. Your job is to check whether it is real, current, and internally consistent — and you should not need to buy anything to do it.',
    clockAngle:
      'The regulations create the paper trail you are checking: CRA Art. 14 records (applies since 11 Sep 2026) and Machinery Reg. Annex III 1.1.9 evidence of intervention (applies 20 Jan 2027). Verification of that evidence is engineered to be free at every tier, permanently — the audience for a piece of evidence is a regulator or an insurer, never an account holder.',
    painPoints: [
      { title: 'A hash chain only proves editing was caught', body: 'A chain rebuilt from genesis after deleting inconvenient records still verifies. Counter-signed head attestation is the part that catches deletion, and you can verify a signature without an account.' },
      { title: 'A label can lie about the bytes', body: 'The firmware says 3.9.0; the supplier’s published hash for 3.9.0 does not match what is on the machine. That mismatch is a first-class, reportable finding — not silently ignored.' },
      { title: 'You need to check, not take their word for it', body: 'Every verification route — Declaration check, manifest diff, bundle re-check, attestation verify — runs with no account, by design.' },
    ],
    proof: [
      { title: 'Free forever, by design', body: 'Declaration check, bundle re-verification, and attestation verification are engineered as always-free — the buyer or auditor is never the paying customer.', href: '/#pricing' },
      { title: 'Counter-signed head attestation', body: 'A signature over the ledger head by a key the operator does not hold — the one thing that catches a ledger that was quietly shortened.', href: `${DEPLOY_BLOB}/ATTEST.md`, external: true },
    ],
    primaryCta: { label: 'Verify a bundle for free', href: '/#products' },
    secondaryCta: { label: 'Read how attestation works', href: `${DEPLOY_BLOB}/ATTEST.md`, external: true },
    images: { hero: 'solution-auditor-hero', supporting: ['solution-auditor-mismatch'] },
  },
  {
    slug: 'ai-ops',
    role: 'AI / ops platform team',
    kicker: 'For teams building on top of the platform layer',
    headline: 'The assurance product sits on a real integration layer — not a demo.',
    lead:
      'NeuralBridge is the FastAPI backend, MCP gateway, and connection model the assurance product is built on. If your team is exposing tools to AI agents or wiring up connection state, this is the layer underneath, not a separate pitch.',
    clockAngle:
      'The compliance clocks (CRA Art. 14 since 11 Sep 2026; Machinery Reg. Annex III 1.1.9 from 20 Jan 2027) are what the assurance layer answers to. The platform layer underneath is judged by a narrower, honest standard: what is actually supported today, not the roadmap.',
    painPoints: [
      { title: 'The platform is intentionally narrow right now', body: 'A FastAPI backend, MCP tool listing and invocation, and a small supported adapter set (PostgreSQL, REST) — not a universal enterprise middleware claim.' },
      { title: 'The dashboard is not yet wired to assurance', body: 'src/dashboard exists as a Next.js console but is not integrated with the assurance product — said plainly, not glossed over.' },
      { title: 'Broad adapter coverage is evolving, not shipped', body: 'Treat anything not marked Supported in the README as evolving. That is the honest line, and it is the one this page holds too.' },
    ],
    proof: [
      { title: 'The platform status table', body: 'What is Supported vs Evolving today, generated from the same README the rest of this site is checked against.', href: '/#platform' },
      { title: 'MCP gateway', body: 'Tool listing and invocation for AI agents, sitting underneath the assurance API.', href: '/#platform' },
    ],
    primaryCta: { label: 'See what is supported today', href: '/#platform' },
    secondaryCta: { label: 'Read the README', href: `${REPO}#readme`, external: true },
    images: { hero: 'solution-aiops-hero', supporting: ['solution-aiops-mcp-gateway', 'solution-aiops-dashboard-unwired'] },
  },
];

export function getSolution(slug: string): SolutionPage | undefined {
  return SOLUTIONS.find((s) => s.slug === slug);
}
