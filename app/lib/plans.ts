// One shared copy of the public plan catalogue, used by PricingPlans (as the
// offline fallback) and anything else on the site that needs a plan's wording.
//
// Source of truth: src/assurance/billing/plans.py::public_catalogue() — this
// is what GET /v1/plans returns from a deployment with no Stripe price env
// vars set. The `blurb` and `includes` strings below are copied from there
// verbatim, so the live table and the fallback table render identically.
// Changing a string in plans.py means changing it here in the same commit;
// docs/claims-registry.md records which code enforces each claim.
//
// Prices (€390/mo, €1,290/mo) are unvalidated hypotheses, not market-tested
// numbers. Cases are NOT metered on any tier: the plan model carries no
// per-case cap and no product-family cap, and nothing here may claim one.

export interface PlanLimits {
  validations_per_day: number | null;
  register_access: boolean;
  verifiable_export: boolean;
  signed_attestation: boolean;
  machine_verification: boolean;
  separations_per_day?: number | null;
  diffs_per_day?: number | null;
  supplier_publish?: boolean;
  ai_control_plane?: boolean;
  ai_reads_per_day?: number | null;
}

export interface Plan {
  tier: 'free' | 'register' | 'cell';
  name: string;
  blurb: string;
  price: string;
  purchasable: boolean;
  includes: string[];
  limits: PlanLimits;
}

/** The one sentence every public surface uses about case volume. */
export const CASES_NOT_METERED = 'Cases are not metered — no per-case cap or charge';

const AI_PAID =
  '/ai control plane: unlimited reads, propose-and-approve WRITEs, bind additional connections, the adapter-call log for your account (held in memory, cleared on restart) and durable plan decisions';

export const FALLBACK_PLANS: Plan[] = [
  {
    tier: 'free',
    name: 'Validator',
    blurb:
      "Check a draft Article 14 filing against the ENISA platform's 39-field specification before you open the platform. No account, nothing recorded.",
    price: 'free',
    purchasable: false,
    includes: [
      '/ai control plane: discover the demo connection and run READ operations (list tables, describe a table, run a SELECT), up to 30 a day — writes need Register or Cell',
      'POST /v1/spec/validate — what is missing, what exceeds a character limit, which listed territories are not EU Member States',
      'GET /v1/spec/fields — the full field specification per track and stage',
      'POST /v1/machine/separation — the ISO/TS 15066 protective separation distance for your cell, term by term, from your own stop figures',
      "POST /v1/machine/bundle/check — re-verify anybody's evidence bundle. Always free: a bundle only a paying customer can check is worth nothing",
      'POST /v1/machinery/diff — whether a machine still matches the configuration it was CE-marked with',
      'POST /v1/fleet/advisory/check — whether one supplier advisory affects one machine',
      'POST /v1/fleet/declaration/check — whether a Declaration of Conformity still describes the machine you were sold. Always free: the person who most needs this is the buyer, not the seller',
      'The offline enrolment kit — `assurance kit run` collects your machines inside your own plant, into your own ledger, with a guard over the socket layer proving nothing left. No account, no upload, and free: if it needed a licence it would need a procurement review, which is the thing it exists to avoid',
      "POST /v1/ledger/attest/verify and GET /v1/ledger/attest/key — check anybody's signed head attestations. Always free: the audience for an attestation is a regulator or an insurer, not an account holder",
      '20 validations and 20 separation calculations per day, per address',
    ],
    limits: {
      validations_per_day: 20,
      register_access: false,
      verifiable_export: false,
      signed_attestation: false,
      machine_verification: false,
      separations_per_day: 20,
      diffs_per_day: 10,
      supplier_publish: false,
      ai_control_plane: false,
      ai_reads_per_day: 30,
    },
  },
  {
    tier: 'register',
    name: 'Register',
    blurb:
      'The Article 14 register for one manufacturer: awareness records, both deadline clocks, triage with the grounds cited, and a hash-chained evidence ledger you can export.',
    price: '€390 / month',
    purchasable: false,
    includes: [
      'Everything in Validator, without the daily cap',
      CASES_NOT_METERED,
      'Awareness records with the reasoning that defends them',
      "Both final-report clocks computed correctly, and the platform's counter defect surfaced rather than inherited",
      'Hash-chained evidence ledger; export refuses if the chain does not verify',
      AI_PAID,
    ],
    limits: {
      validations_per_day: null,
      register_access: true,
      verifiable_export: true,
      signed_attestation: false,
      machine_verification: false,
      separations_per_day: null,
      diffs_per_day: null,
      supplier_publish: false,
      ai_control_plane: true,
      ai_reads_per_day: null,
    },
  },
  {
    tier: 'cell',
    name: 'Cell',
    blurb:
      'For a manufacturer or integrator shipping machines: everything in Register, plus machine safety assurance: check a recorded run against the safety envelope you declared, track what safety software is on each machine and who changed it, and know which safety functions still have evidence that describes the machine as it is today.',
    price: '€1,290 / month',
    purchasable: false,
    includes: [
      'Everything in Register',
      AI_PAID,
      'Machine safety verification: POST /v1/machine/verify checks a recorded run against a declared safety envelope and seals the result',
      'Separation, speed, workspace, stop characterisation, power-and-force and mode-consistency checks, each with its worst margin',
      'Evidence bundles anyone can re-verify without an account',
      'Machinery Regulation Annex III 1.1.9: the safety software manifest, the intervention record, and the machine passport',
      'Coverage: which declared safety functions still have valid evidence, and which intervention invalidated the rest',
      'Fleet: every enrolled machine ranked worst-first, and a supplier advisory fanned out to serial numbers and the safety functions it puts in question',
      'Declarations of Conformity bound to a configuration hash, so a declaration can be shown to have stopped describing the machine',
      CASES_NOT_METERED,
      'Change-assurance cases: open, claim, re-verify and close a ChangeAssuranceCase over /v1/change/*; closure is a named human decision',
      'Counter-signed head attestation: POST /v1/ledger/attest signs the head of your ledger with a key you do not hold, so a rewind contradicts a signed statement. Your ledger is never uploaded — we sign three numbers and never see a record',
    ],
    limits: {
      validations_per_day: null,
      register_access: true,
      verifiable_export: true,
      signed_attestation: true,
      machine_verification: true,
      separations_per_day: null,
      diffs_per_day: null,
      supplier_publish: false,
      ai_control_plane: true,
      ai_reads_per_day: null,
    },
  },
];
