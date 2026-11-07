// The customer journey, in order: enrol a machine, collect evidence, verify, advisory/finding,
// human decision, re-verify, passport/export. Each step says where it is done on a hosted
// deployment (a route the workspace calls, if this build has an API address) and where it is done
// offline or self-hosted (a CLI verb that runs on the customer's own machine).
//
// Every route and verb below is checked against public/capabilities.json (which is generated from
// src/assurance/capabilities.py) by tests/test_site_workspace_consolidation.py, so this table
// cannot name something the product does not have.

export type JourneyStep = {
  id: string;
  label: string;
  /** Where this step is done in the /assurance workspace, or null when the step happens elsewhere. */
  href: string | null;
  /** The hosted route(s) behind it, in the capability catalogue's own spelling. */
  hosted: string[];
  /** What the hosted service does and does not do for this step. */
  hostedNote: string;
  /** The offline / self-hosted CLI verb(s) (`assurance <verb>`). */
  offline: string[];
  /** Who acts. Software drafts; the named people decide. */
  actor: string;
};

export const JOURNEY: JourneyStep[] = [
  {
    id: 'enrol',
    label: 'Enrol a machine',
    href: '/assurance#aw-enrol',
    hosted: ['POST /v1/machinery/enrol'],
    hostedNote: 'A named person declares the machine; a baseline is sealed with a receipt.',
    offline: ['machinery enrol'],
    actor: 'A named person',
  },
  {
    id: 'collect',
    label: 'Collect evidence',
    href: '/assurance#aw-fleet',
    hosted: ['POST /v1/watch/report'],
    hostedNote:
      'The hosted service does not collect from your machines. Collection runs on your own side; the hosted API only records what your Watch reports, and the Fleet panel shows it as reported by you.',
    offline: ['collect run', 'kit run', 'watch run', 'watch push'],
    actor: 'Your own collection run',
  },
  {
    id: 'verify',
    label: 'Verify the record',
    href: '/assurance#aw-ledger-verify',
    hosted: ['GET /v1/ledger/verify', 'POST /v1/evidence/verify'],
    hostedNote: 'The chain is recomputed on each request; unchecked and incomplete are reported as such, never as a pass.',
    offline: ['art14 verify', 'evidence verify'],
    actor: 'Software recomputes; a person reads the result',
  },
  {
    id: 'advisory',
    label: 'Advisory or finding',
    href: '/assurance#aw-advisories',
    hosted: ['POST /v1/fleet/advisory'],
    hostedNote: 'Which declared functions an advisory touches. A finding is a statement about evidence, not a safety conclusion.',
    offline: ['fleet advisory', 'watch open-case'],
    actor: 'Software drafts; a named person opens a case',
  },
  {
    id: 'decision',
    label: 'Human decision',
    href: '/assurance#aw-cases',
    hosted: ['POST /v1/change/cases/{case_id}/decision'],
    hostedNote: 'Needs a named operator with the decider role. Software never decides or closes a case.',
    offline: ['change decide'],
    actor: 'A named decider',
  },
  {
    id: 'reverify',
    label: 'Re-verify',
    href: '/assurance#aw-cases',
    hosted: ['POST /v1/change/cases/{case_id}/reverification'],
    hostedNote: 'Records the re-verification a case requires; a waiver is a separate, named human act.',
    offline: ['change reverify'],
    actor: 'A named person',
  },
  {
    id: 'passport',
    label: 'Passport and export',
    href: '/assurance#aw-passport',
    hosted: ['POST /v1/machinery/passport', 'GET /v1/cases/{case_id}/export'],
    hostedNote: 'An export is only as complete as its chain check says; a hosted export carries a signed anchor only once the operator has signed the ledger.',
    offline: ['machinery passport', 'art14 export'],
    actor: 'Software assembles; people review',
  },
];

export type StepAvailability = 'hosted' | 'offline_only';

/**
 * Whether the step can be done from this deployment's workspace. The hosted API must have an
 * address in this build; the collect step is never done by the hosted service.
 */
export function availability(step: JourneyStep, hostedConfigured: boolean): StepAvailability {
  if (step.id === 'collect') return 'offline_only';
  return hostedConfigured ? 'hosted' : 'offline_only';
}
