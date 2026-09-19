// Dual illustration packs, keyed by the slot name used across the site.
// See app/DESIGN.md → Imagery for the file layout and rotation rules.
//
// `a` and `b` are two independently generated photoreal frames of the same
// scene — never a fake vs. a real photo, and never two crops of the same
// file. Each carries its own alt text because they are genuinely different
// compositions; when only `a` exists (a portrait crop, or
// solution-aiops-mcp-gateway, whose source shipped 0 bytes for `b`), the
// slot has no `b` and renders as a single static image. The source archives
// have been extracted into public/images/variants/{a,b} and are not kept in
// the repo.

export interface ImageVariant {
  src: string;
  alt: string;
}

export interface ImageSlot {
  /** a is required; every usable frame from the "images" pack. */
  a: ImageVariant;
  /** b is the "pack" pack's frame of the same scene, when it exists and isn't corrupt. */
  b?: ImageVariant;
  /** 4:5 mobile portrait crop, "images" pack only. */
  portraitA?: ImageVariant;
}

const A = '/images/variants/a/images';
const B = '/images/variants/b/images';

export const IMAGES: Record<string, ImageSlot> = {
  'hero-hash-chained-cell': {
    a: { src: `${A}/hero-hash-chained-cell.jpg`, alt: 'Night-shift palletising robot cell behind a safety fence with a cabinet display showing a configuration hash and timestamp.' },
    b: { src: `${B}/hero-hash-chained-cell.jpg`, alt: 'Night view of a fenced palletising robot cell with a cabinet display showing a machine hash and timestamp.' },
    portraitA: { src: `${A}/hero-hash-chained-cell-portrait.jpg`, alt: 'Vertical view of a palletising cell at night with a hashed local panel and scanner zone marks.' },
  },
  'hero-airgap-kit': {
    a: { src: `${A}/hero-airgap-kit.jpg`, alt: 'Plant engineer running an air-gapped enrolment kit at an open control cabinet with the network unplugged.' },
    b: { src: `${B}/hero-airgap-kit.jpg`, alt: 'Engineer running an air-gapped enrolment kit at a factory control cabinet with network ports capped.' },
    portraitA: { src: `${A}/hero-airgap-kit-portrait.jpg`, alt: 'Vertical portrait of a plant engineer with an offline rugged laptop and capped Ethernet at a control cabinet.' },
  },
  'strip-cra-clock': {
    a: { src: `${A}/strip-cra-clock.jpg`, alt: 'Compliance desk with a 24-hour clock and an Article 14 early-warning dossier overlooking a European plant.' },
    b: { src: `${B}/strip-cra-clock.jpg`, alt: 'Compliance officer reviewing an early-warning dossier under a 24-hour clock.' },
  },
  'strip-machinery-annex': {
    a: { src: `${A}/strip-machinery-annex.jpg`, alt: 'Open safety cabinet with labelled firmware and a printed inventory of safety-relevant software.' },
    b: { src: `${B}/strip-machinery-annex.jpg`, alt: 'Open safety cabinet showing labelled PLC modules and a printed safety-software inventory.' },
  },
  'strip-hash-chain': {
    a: { src: `${A}/strip-hash-chain.jpg`, alt: 'Bound evidence pack with printed hash lines, tamper-evident tape, and a signature card.' },
    b: { src: `${B}/strip-hash-chain.jpg`, alt: 'Bound paper evidence pack sealed with tamper tape and a counter-signature card.' },
  },
  'strip-offline-kit': {
    a: { src: `${A}/strip-offline-kit.jpg`, alt: 'Disconnected rugged laptop on a plant desk with a printed list of local kit files.' },
    b: { src: `${B}/strip-offline-kit.jpg`, alt: 'Rugged plant laptop showing local kit files with network ports unused.' },
  },
  'intent-fleet-advisory': {
    a: { src: `${A}/intent-fleet-advisory.jpg`, alt: 'Overhead of palletising lines with one cell lit and an advisory matched to serial AR-7#0412 on Plant 2 Line 4.' },
    b: { src: `${B}/intent-fleet-advisory.jpg`, alt: 'Factory hall of palletising cells with a supplier advisory clipped to Plant 2 Line 4.' },
  },
  'playground-validate-placeholder': {
    a: { src: `${A}/playground-validate-placeholder.jpg`, alt: 'Marked-up Article 14 draft on a bench noting missing fields and that Switzerland is not an EU Member State.' },
    b: { src: `${B}/playground-validate-placeholder.jpg`, alt: 'Marked-up Article 14 early-warning form noting Switzerland is not an EU Member State.' },
  },
  'card-plan-validator': {
    a: { src: `${A}/card-plan-validator.jpg`, alt: 'Clean bench with a free verification stamp and paper checklist, no account portal.' },
    b: { src: `${B}/card-plan-validator.jpg`, alt: 'Verification record stamped FREE on a navy inspection bench.' },
  },
  'card-plan-register': {
    a: { src: `${A}/card-plan-register.jpg`, alt: 'Manufacturer archive room with product-family folders and a bound hash-chained register.' },
    b: { src: `${B}/card-plan-register.jpg`, alt: 'Archive room of product-family boxes with an open evidence register.' },
  },
  'card-plan-cell': {
    a: { src: `${A}/card-plan-cell.jpg`, alt: 'Palletising cell with a Declaration of Conformity on the fence and a firmware configuration plate.' },
    b: { src: `${B}/card-plan-cell.jpg`, alt: 'Robot cell fence holding a Declaration of Conformity and an AR-7 configuration plate.' },
  },
  'card-engine-machine-safety': {
    a: { src: `${A}/card-engine-machine-safety.jpg`, alt: 'Technician standing outside marked floor separation tape while a robot cell runs inside its safety envelope.' },
    b: { src: `${B}/card-engine-machine-safety.jpg`, alt: 'Technician standing outside marked collaborative workspace around a robot arm.' },
  },
  'card-engine-annex-iii': {
    a: { src: `${A}/card-engine-annex-iii.jpg`, alt: 'HMI and paper intervention record showing which safety software is installed and who last changed it.' },
    b: { src: `${B}/card-engine-annex-iii.jpg`, alt: 'Safety HMI and intervention record on an open electrical cabinet.' },
  },
  'card-engine-fleet': {
    a: { src: `${A}/card-engine-fleet.jpg`, alt: 'Row of machine serial plates with a supplier bulletin matched to a single serial identity.' },
    b: { src: `${B}/card-engine-fleet.jpg`, alt: 'Supplier bulletin clipped under serial plate AR-7#0412 on a row of identical machines.' },
  },
  'card-engine-watch': {
    a: { src: `${A}/card-engine-watch.jpg`, alt: 'Empty night factory aisle with a single panel lamp glowing on a distant cabinet.' },
    b: { src: `${B}/card-engine-watch.jpg`, alt: 'Empty night factory with a single amber cabinet lamp glowing at the far end.' },
  },
  'card-engine-attest': {
    a: { src: `${A}/card-engine-attest.jpg`, alt: 'Two different keys beside a signed ledger-head print bearing a hash.' },
    b: { src: `${B}/card-engine-attest.jpg`, alt: 'Operator and attest keys beside a printed ledger head awaiting a counter-signature.' },
  },
  'card-engine-kit': {
    a: { src: `${A}/card-engine-kit.jpg`, alt: 'Printed kit file list beside a rugged laptop with its Ethernet cable unplugged.' },
    b: { src: `${B}/card-engine-kit.jpg`, alt: 'Printed kit file list next to a disconnected rugged laptop and a port cap.' },
  },
  'card-api-assurance': {
    a: { src: `${A}/card-api-assurance.jpg`, alt: 'Small server rack beside a terminal showing GET /v1/plans and POST /v1/spec/validate.' },
    b: { src: `${B}/card-api-assurance.jpg`, alt: 'Plant server closet monitor listing GET /v1/plans and POST /v1/spec/validate.' },
  },
  'platform-integration-hub': {
    a: { src: `${A}/platform-integration-hub.jpg`, alt: 'Ops desk with an MCP tool list, PostgreSQL and REST gateways, and a small FastAPI server.' },
    b: { src: `${B}/platform-integration-hub.jpg`, alt: 'Desk with PostgreSQL and REST gateway boxes beside a FastAPI server and MCP tool list.' },
  },
  'pricing-three-tiers': {
    a: { src: `${A}/pricing-three-tiers.jpg`, alt: 'Three objects on a bench representing Validator, Register, and Cell plans.' },
    b: { src: `${B}/pricing-three-tiers.jpg`, alt: 'Free validator stamp, monthly register book, and sealed cell evidence case on a bench.' },
  },
  'solution-manufacturer-hero': {
    a: { src: `${A}/solution-manufacturer-hero.jpg`, alt: 'Manufacturer engineer signing a Declaration of Conformity in front of a running palletising cell.' },
    b: { src: `${B}/solution-manufacturer-hero.jpg`, alt: 'Declaration of Conformity being signed in front of a live palletising cell.' },
  },
  'solution-manufacturer-drift': {
    a: { src: `${A}/solution-manufacturer-drift.jpg`, alt: 'Engineer updating a safety controller while the Declaration of Conformity binder stays closed on a shelf.' },
    b: { src: `${B}/solution-manufacturer-drift.jpg`, alt: 'Technician updating a safety controller while the Declaration binder stays closed on a shelf.' },
  },
  'solution-manufacturer-fanout': {
    a: { src: `${A}/solution-manufacturer-fanout.jpg`, alt: 'A single supplier advisory held against a row of engraved machine serial plates.' },
    b: { src: `${B}/solution-manufacturer-fanout.jpg`, alt: 'Hand holding one supplier advisory above rows of metal serial plates.' },
  },
  'solution-plant-operator-hero': {
    a: { src: `${A}/solution-plant-operator-hero.jpg`, alt: 'Night-shift operator at a palletising cell after remote service has left, with only a coiled cable on the bench.' },
    b: { src: `${B}/solution-plant-operator-hero.jpg`, alt: 'Night-shift operator standing at a fenced cell after remote service has left.' },
  },
  'solution-plant-operator-inspector': {
    a: { src: `${A}/solution-plant-operator-inspector.jpg`, alt: 'Inspector and plant operator reviewing a local paper ledger at a yellow safety fence.' },
    b: { src: `${B}/solution-plant-operator-inspector.jpg`, alt: 'Operator showing an inspector a local offline ledger at a robot cell fence.' },
  },
  'solution-compliance-hero': {
    a: { src: `${A}/solution-compliance-hero.jpg`, alt: 'Compliance officer reviewing a hash evidence pack at night with a 24-hour clock and a closed spreadsheet.' },
    b: { src: `${B}/solution-compliance-hero.jpg`, alt: 'Compliance officer reviewing an evidence pack at night with a wall clock behind her.' },
  },
  'solution-compliance-clocks': {
    a: { src: `${A}/solution-compliance-clocks.jpg`, alt: 'Two clocks and rubber stamps marking a 24-hour early warning and a later report deadline.' },
    b: { src: `${B}/solution-compliance-clocks.jpg`, alt: 'Two analog clocks with early-warning and report-deadline stamps.' },
  },
  'solution-auditor-hero': {
    a: { src: `${A}/solution-auditor-hero.jpg`, alt: 'Independent auditor checking a printed hash list and USB evidence bundle on a personal laptop.' },
    b: { src: `${B}/solution-auditor-hero.jpg`, alt: 'Auditor comparing on-screen hashes with a signed paper evidence list.' },
  },
  'solution-auditor-mismatch': {
    a: { src: `${A}/solution-auditor-mismatch.jpg`, alt: 'Machine nameplate version 3.9.0 next to a maintenance stick whose hash does not match.' },
    b: { src: `${B}/solution-auditor-mismatch.jpg`, alt: 'Version plate 3.9.0 next to mismatched hashes on paper and a USB stick tag.' },
  },
  'solution-aiops-hero': {
    a: { src: `${A}/solution-aiops-hero.jpg`, alt: 'Two engineers reviewing MCP tools and FastAPI routes GET /v1/plans and POST /v1/spec/validate.' },
    b: { src: `${B}/solution-aiops-hero.jpg`, alt: 'Two engineers reviewing MCP tools and FastAPI plan routes on side-by-side monitors.' },
  },
  // Pack zip's copy of this file was 0 bytes — ship the images-zip version
  // only, as a single (non-rotating) image, per this stage's instructions.
  'solution-aiops-mcp-gateway': {
    a: { src: `${A}/solution-aiops-mcp-gateway.jpg`, alt: 'Patch panel with only the PostgreSQL and REST ports cabled and all other ports empty.' },
  },
  'solution-aiops-dashboard-unwired': {
    a: { src: `${A}/solution-aiops-dashboard-unwired.jpg`, alt: 'Empty connections console beside a separate assurance ledger box and paper log printer.' },
    b: { src: `${B}/solution-aiops-dashboard-unwired.jpg`, alt: 'Empty web console next to a separate industrial PC with a paper production log.' },
  },
  'api-fastapi-docs': {
    a: { src: `${A}/api-fastapi-docs.jpg`, alt: 'Engineer reading FastAPI route notes beside a palletising cell.' },
    b: { src: `${B}/api-fastapi-docs.jpg`, alt: 'Engineer holding a printed FastAPI route list in front of a robot cell.' },
  },
  'docs-offline-enrolment': {
    a: { src: `${A}/docs-offline-enrolment.jpg`, alt: 'Offline enrolment kit on a plant laptop with outbound Ethernet ports capped.' },
    b: { src: `${B}/docs-offline-enrolment.jpg`, alt: 'Rugged plant PC running a local enrolment kit check with outbound ports capped.' },
  },
  // src/dashboard — never wired to the homepage "live console"; used only
  // inside the dashboard app itself (or not at all from app/ yet).
  'dashboard-empty-connections': {
    a: { src: `${A}/dashboard/dashboard-empty-connections.jpg`, alt: 'Empty industrial gateway faceplate labelled PostgreSQL and REST.' },
    b: { src: `${B}/dashboard/dashboard-empty-connections.jpg`, alt: 'Empty industrial ports labelled PostgreSQL and REST.' },
  },
  'dashboard-audit-trail': {
    a: { src: `${A}/dashboard/dashboard-audit-trail.jpg`, alt: 'Paper audit log and a small terminal listing the same tool invocations.' },
    b: { src: `${B}/dashboard/dashboard-audit-trail.jpg`, alt: 'Paper audit log placed beside a tablet showing the same tool-invocation hashes.' },
  },
  'dashboard-login-plant': {
    a: { src: `${A}/dashboard/dashboard-login-plant.jpg`, alt: 'View from a dark server-room window onto a palletising robot cell behind a yellow fence.' },
    b: { src: `${B}/dashboard/dashboard-login-plant.jpg`, alt: 'Dark server room looking through a window onto a robot palletising cell.' },
  },
};

export function imageSlot(key: keyof typeof IMAGES): ImageSlot {
  const slot = IMAGES[key];
  if (!slot) throw new Error(`Unknown image slot: ${key}`);
  return slot;
}
