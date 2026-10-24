import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { classify, describeOutcome } from '../app/lib/assuranceApi';

// /verify against the REAL local Assurance API (nothing mocked). Run via
// scripts/e2e-assurance.sh, which starts the API and a Next server built with
// NEXT_PUBLIC_ASSURANCE_API_URL, e.g.
//   API_PORT=18100 WEB_PORT=18101 scripts/e2e-assurance.sh \
//     --project=desktop-chromium -g "Evidence verify"
//
// The evidence files are not hand-written: a Python snippet drives the real
// EvidenceLedger / ChangeAssuranceCase flow, the real machine-verification
// engine and the real attestation signer (the same builder the API tests use,
// tests/test_assurance_evidence_api.py) and writes what they emit.

const py = process.env.ASSURANCE_E2E_PYTHON || 'python';
const apiConfigured = !!process.env.NEXT_PUBLIC_ASSURANCE_API_URL;

const BUILDER = `
import json, sys, tempfile
from datetime import UTC, datetime
from pathlib import Path
from assurance.attest import AttestationLog, SigningKey, attest
from assurance.attest.attestation import AttestationBasis, LedgerHead
from assurance.evidence.ledger import EvidenceLedger
from tests.test_assurance_evidence_api import build_real_ledger
from tests.test_assurance_change import seal_a_real_verification

work = Path(sys.argv[1])
ledger, case_id = build_real_ledger(work / "ledger.db")
key = SigningKey.generate()
log = AttestationLog(work / "attest.jsonl")
attest(ledger, key, log, note="e2e")
machine = seal_a_real_verification(
    EvidenceLedger(work / "machine.db"), when=datetime(2026, 2, 9, tzinfo=UTC))
anchor = log.require_last().to_dict()
# A head the signer was only TOLD (what POST /v1/ledger/attest signs), under its own key.
declared_key = SigningKey.generate()
head = ledger.entries()[-1]
declared = attest(
    LedgerHead(len(ledger.entries()), head.seq, head.link_hash, AttestationBasis.DECLARED_BY_HOLDER),
    declared_key, AttestationLog(work / "declared.jsonl"))
declared_whole = ledger.export()
declared_whole["anchor"] = declared.to_dict()
out = {
    "whole": json.dumps(ledger.export()),
    "whole_anchored": json.dumps(ledger.export(anchor=anchor)),
    "case_anchored": json.dumps(ledger.export(subject=case_id, anchor=anchor)),
    "case_skeleton_anchored": json.dumps(ledger.export(subject=case_id, anchor=anchor, skeleton=True)),
    "declared_whole": json.dumps(declared_whole),
    "declared_public_key": declared_key.verifying.pem(),
    "case": json.dumps(ledger.export(subject=case_id)),
    "machine": json.dumps(machine.to_dict()),
    "attestations": (work / "attest.jsonl").read_text(),
    "public_key": key.verifying.pem(),
}
(work / "fixtures.json").write_text(json.dumps(out))
`;

type Fixtures = {
  whole: string;
  whole_anchored: string;
  case_anchored: string;
  case_skeleton_anchored: string;
  declared_whole: string;
  declared_public_key: string;
  case: string;
  machine: string;
  attestations: string;
  public_key: string;
};

function build(): Fixtures {
  const work = mkdtempSync(join(tmpdir(), 'evidence-verify-'));
  execFileSync(py, ['-c', BUILDER, work], {
    cwd: process.cwd(),
    env: { ...process.env, PYTHONPATH: join(process.cwd(), 'src') + ':' + process.cwd() },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return JSON.parse(readFileSync(join(work, 'fixtures.json'), 'utf8'));
}

test.describe.configure({ mode: 'serial' });

test.describe('Evidence verify page', () => {
  let fx: Fixtures;
  test.beforeAll(() => {
    test.skip(!apiConfigured, 'Set NEXT_PUBLIC_ASSURANCE_API_URL (run scripts/e2e-assurance.sh) — not faking a result.');
    fx = build();
  });

  async function open(page: Page) {
    await page.goto('/verify');
    await expect(page.getByTestId('evidence-verifier')).toHaveAttribute('data-ready', 'true');
  }

  async function upload(page: Page, name: string, text: string) {
    await open(page);
    await page.getByTestId('ev-file').setInputFiles({ name, mimeType: 'application/json', buffer: Buffer.from(text) });
    await expect(page.getByTestId('ev-filename')).toContainText(name);
    await page.getByTestId('ev-run').click();
  }

  test('a genuine ledger export: facts, assumptions and limits are shown apart, and never a bare valid', async ({ page }) => {
    await upload(page, 'export.json', fx.whole);
    const headline = page.getByTestId('ev-headline');
    await expect(headline).toHaveText('No inconsistency found in the checks that ran');
    // not green: nothing shows the export is complete, and the colour must not say it is
    await expect(headline).toHaveAttribute('data-tone', 'caution');
    await expect(page.getByTestId('ev-kind')).toContainText('Ledger export');
    await expect(page.getByTestId('ev-kind')).toContainText('whole ledger');

    const verified = page.getByTestId('ev-verified');
    await expect(verified).toContainText('still hashes to the content hash recorded for it');
    await expect(verified).toContainText('actor column equals the actor sealed inside its evidence');
    await expect(verified).toContainText('chains to the genesis value');
    await expect(page.getByTestId('ev-problems')).toHaveCount(0);

    await expect(page.getByTestId('ev-assumed')).toContainText('whatever the writer declared');
    await expect(page.getByTestId('ev-assumed')).toContainText('python -m assurance evidence verify');
    const limits = page.getByTestId('ev-notchecked');
    await expect(limits).toContainText('not that it matches the ledger its operator holds');
    await expect(limits).toContainText('signed head attestation');
    await expect(page.getByTestId('ev-head')).toContainText('link hash');

    const body = (await page.getByTestId('ev-result').innerText()).toLowerCase();
    expect(body).not.toMatch(/\bvalid\b|✔|✓|certified|compliant|proof of safety/);
    await expect(page.getByTestId('ev-stateless')).toContainText('Nothing is stored');
  });

  test('a one-case export says what a subject bundle cannot show', async ({ page }) => {
    await upload(page, 'case.json', fx.case);
    await expect(page.getByTestId('ev-headline')).toHaveText('No inconsistency found in the checks that ran');
    await expect(page.getByTestId('ev-kind')).toContainText('subject');
    await expect(page.getByTestId('ev-notchecked')).toContainText("holds one subject's entries only");
    await expect(page.getByTestId('ev-head')).toHaveCount(0);
  });

  test('an untouched default one-case export with the right key is "could not be established", not "problems found"', async ({ page }) => {
    await open(page);
    await page.getByTestId('ev-text').fill(fx.case_anchored);
    await page.getByTestId('ev-key').fill(fx.public_key);
    await page.getByTestId('ev-run').click();
    const headline = page.getByTestId('ev-headline');
    await expect(headline).toContainText('Could not be established');
    await expect(headline).toHaveAttribute('data-outcome', 'not_established');
    await expect(headline).toHaveAttribute('data-tone', 'caution'); // amber, not the danger colour
    await expect(page.getByTestId('ev-summary')).toContainText('Completeness could not be established');
    await expect(page.getByTestId('ev-summary')).toContainText('skeleton=true');
    await expect(page.getByTestId('ev-unestablished')).toContainText('skeleton');
    await expect(page.getByTestId('ev-problems')).toHaveCount(0);
    await expect(page.getByTestId('ev-result')).not.toContainText('Problems found');
    await expect(page.getByTestId('ev-result')).not.toContainText('not what the exporter wrote');
  });

  test('the same case with its skeleton, checked with the key, is anchored and green', async ({ page }) => {
    await open(page);
    await page.getByTestId('ev-text').fill(fx.case_skeleton_anchored);
    await page.getByTestId('ev-key').fill(fx.public_key);
    await page.getByTestId('ev-run').click();
    const headline = page.getByTestId('ev-headline');
    await expect(headline).toHaveText('No inconsistency found in the checks that ran');
    await expect(headline).toHaveAttribute('data-tone', 'success');
    await expect(page.getByTestId('ev-kind')).toContainText('read_from_ledger');
    await expect(page.getByTestId('ev-unestablished')).toHaveCount(0);
  });

  test('a head the signer was only told is "declared", amber, and never anchored', async ({ page }) => {
    await open(page);
    await page.getByTestId('ev-text').fill(fx.declared_whole);
    await page.getByTestId('ev-key').fill(fx.declared_public_key);
    await page.getByTestId('ev-run').click();
    const headline = page.getByTestId('ev-headline');
    await expect(headline).toContainText('only declared');
    await expect(headline).toHaveAttribute('data-tone', 'caution');
    await expect(page.getByTestId('ev-kind')).toContainText('DECLARED');
    await expect(page.getByTestId('ev-kind')).toContainText('declared_by_holder');
    await expect(page.getByTestId('ev-kind')).not.toContainText('read from the ledger');
    await expect(page.getByTestId('ev-summary')).toContainText('never read the chain');
    await expect(page.getByTestId('ev-notchecked').first()).toContainText('COMPLETENESS NOT CHECKED');
  });

  test('the key box says a one-case export needs the skeleton, and the page says the key is also for ledger exports', async ({ page }) => {
    await open(page);
    await page.getByTestId('ev-text').fill(fx.case_anchored);
    await expect(page.getByTestId('ev-key')).toBeVisible(); // opened by the signed anchor in the file
    await expect(page.getByText('?skeleton=true').first()).toBeVisible();
    await expect(page.getByTestId('ev-stateless')).toContainText('to check a ledger export against its signed head');
  });

  test('changing one character of a hash is reported as a problem, with no whole-file facts', async ({ page }) => {
    const m = /"content_hash": "([0-9a-f]{64})"/.exec(fx.whole);
    expect(m).not.toBeNull();
    const hash = m![1];
    const flipped = (hash[0] === '0' ? '1' : '0') + hash.slice(1);
    const tampered = fx.whole.replace(hash, flipped);
    expect(tampered.length).toBe(fx.whole.length); // exactly one character differs

    await upload(page, 'tampered.json', tampered);
    await expect(page.getByTestId('ev-headline')).toHaveText('Problems found');
    await expect(page.getByTestId('ev-problems')).toBeVisible();
    await expect(page.getByTestId('ev-verified')).not.toContainText('genesis');
    await expect(page.getByTestId('ev-result')).not.toContainText('No inconsistency found');
  });

  test('an edited actor column is found', async ({ page }) => {
    const bundle = JSON.parse(fx.whole);
    bundle.entries[0].actor = 'someone.else';
    await upload(page, 'actor.json', JSON.stringify(bundle));
    await expect(page.getByTestId('ev-headline')).toHaveText('Problems found');
    await expect(page.getByTestId('ev-problems')).toContainText('recorded actor');
  });

  test('garbage is a structured result, not an error page', async ({ page }) => {
    await upload(page, 'notes.txt', 'this is not json at all');
    await expect(page.getByTestId('ev-headline')).toHaveText('Could not read this file — nothing was checked');
    await expect(page.getByTestId('ev-problems')).toContainText('not valid JSON');
    await expect(page.getByTestId('ev-kind')).toContainText('Not recognised');
    await expect(page.getByTestId('ev-error')).toHaveCount(0);
  });

  test('a JSON file of another kind says what is supported', async ({ page }) => {
    await upload(page, 'other.json', '{"hello": "world"}');
    await expect(page.getByTestId('ev-headline')).toHaveText('Not a file this page can check');
    await expect(page.getByTestId('ev-notchecked')).toContainText('machine verification bundle');
  });

  test('a duplicate key is refused rather than resolved', async ({ page }) => {
    await upload(page, 'dup.json', fx.whole.slice(0, -1) + ', "subject": "x"}');
    await expect(page.getByTestId('ev-headline')).toHaveText('Could not read this file — nothing was checked');
    await expect(page.getByTestId('ev-problems')).toContainText('appears twice');
  });

  test('a machine bundle shows the recorded tier and what it cannot show', async ({ page }) => {
    await upload(page, 'bundle.json', fx.machine);
    await expect(page.getByTestId('ev-headline')).toHaveText('No inconsistency found in the checks that ran');
    await expect(page.getByTestId('ev-kind')).toContainText('Machine verification bundle');
    const tier = page.getByTestId('ev-tier');
    await expect(tier).toContainText('assurance tier');
    await expect(tier).toContainText('physical machine');
    await expect(tier).toContainText('as recorded in the file');
    await expect(tier).toContainText('declared by the filer');
    await expect(page.getByTestId('ev-notchecked')).toContainText('a seal is not a signature');
    await expect(page.getByTestId('ev-notchecked')).toContainText('nothing here shows the machine behaved');

    const bundle = JSON.parse(fx.machine);
    bundle.result.tier = 'certified';
    await page.getByTestId('ev-text').fill(JSON.stringify(bundle));
    await page.getByTestId('ev-run').click();
    await expect(page.getByTestId('ev-headline')).toHaveText('Problems found');
  });

  test('an attestation log: structure only without the key (never a pass), signatures with it', async ({ page }) => {
    await open(page);
    await page.getByTestId('ev-text').fill(fx.attestations);
    await page.getByTestId('ev-run').click();
    await expect(page.getByTestId('ev-kind')).toContainText('attestation log');
    await expect(page.getByTestId('ev-kind')).toContainText('signatures NOT verified');
    await expect(page.getByTestId('ev-headline')).toHaveText('Structure only — no signature was checked');
    await expect(page.getByTestId('ev-result')).not.toContainText('No inconsistency found');
    await expect(page.getByTestId('ev-notchecked')).toContainText('signatures were NOT verified');
    await expect(page.getByTestId('ev-notchecked')).toContainText('most recent attestation');
    await expect(page.getByTestId('ev-verified')).not.toContainText('signature(s) verify');

    await page.getByTestId('ev-key').fill(fx.public_key);
    await page.getByTestId('ev-run').click();
    await expect(page.getByTestId('ev-headline')).toHaveText('No inconsistency found in the checks that ran');
    await expect(page.getByTestId('ev-verified')).toContainText('signature(s) verify against the public key you supplied');
    await expect(page.getByTestId('ev-assumed')).toContainText('channel');
  });

  test('a private key is refused in the browser and never sent', async ({ page }) => {
    await open(page);
    let sent = false;
    page.on('request', (r) => {
      if (r.url().includes('/v1/evidence/verify')) sent = true;
    });
    await page.getByTestId('ev-text').fill(fx.attestations);
    await page.getByTestId('ev-key').fill('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----');
    await page.getByTestId('ev-run').click();
    await expect(page.getByTestId('ev-error')).toContainText('private key');
    expect(sent).toBe(false);
  });

  test('the public key is not in the request URL', async ({ page }) => {
    await open(page);
    const urls: string[] = [];
    page.on('request', (r) => {
      if (r.url().includes('/v1/evidence/verify')) urls.push(r.url());
    });
    await page.getByTestId('ev-text').fill(fx.attestations);
    await page.getByTestId('ev-key').fill(fx.public_key);
    await page.getByTestId('ev-run').click();
    await expect(page.getByTestId('ev-headline')).toBeVisible();
    expect(urls.length).toBeGreaterThan(0);
    for (const u of urls) expect(u).not.toMatch(/\?|PUBLIC|MCow/);
  });

  test('the offline verifier is pointed to', async ({ page }) => {
    await page.goto('/verify');
    await expect(page.locator('#offline')).toContainText('python -m assurance evidence verify');
  });
});

// Needs a second Next server built WITHOUT NEXT_PUBLIC_ASSURANCE_API_URL:
//   PLAYWRIGHT_NO_API_BASE_URL=http://127.0.0.1:18102 npx playwright test ... -g "no API configured"
test.describe('Evidence verify page, no API configured', () => {
  test('says plainly that nothing can be checked and does not fake a result', async ({ page }) => {
    const base = process.env.PLAYWRIGHT_NO_API_BASE_URL;
    test.skip(!base, 'Set PLAYWRIGHT_NO_API_BASE_URL to a Next server built without NEXT_PUBLIC_ASSURANCE_API_URL.');
    await page.goto(`${base}/verify`);
    await expect(page.getByTestId('ev-no-api')).toContainText('No API is configured');
    await page.getByTestId('ev-text').fill('{"entries": []}');
    await page.getByTestId('ev-run').click();
    await expect(page.getByTestId('ev-error')).toContainText('cannot check anything and will not pretend to');
    await expect(page.getByTestId('ev-headline')).toHaveCount(0);
  });
});

// Pure functions of the API client: no server needed.
test.describe('A 409 that is a finding keeps its words and its advice', () => {
  test('anchor_contradicts_ledger has its own heading and shows the keep-the-evidence advice with the refusal', () => {
    const body = {
      detail: {
        error: 'anchor_contradicts_ledger',
        finding: 'refusing to export: the ledger holds 2 record(s), but attestation 1 signed for 3.',
        remedy: 'Preserve the ledger and the attestation log as they are.',
      },
    };
    const o = classify(409, body);
    expect(o.kind).toBe('conflict');
    if (o.kind !== 'conflict') return;
    const d = describeOutcome(o);
    expect(d.heading).toContain('The export contradicts a signed ledger head');
    expect(d.heading).not.toContain('Not allowed in the current state');
    expect(d.text).toContain('the ledger holds 2 record(s)');
    expect(d.remedy).toContain('Preserve the ledger and the attestation log');
  });

  test('a plain 409 keeps the generic heading and the server\'s own words', () => {
    const o = classify(409, { detail: 'the case is already closed' });
    expect(o.kind).toBe('conflict');
    if (o.kind !== 'conflict') return;
    const d = describeOutcome(o);
    expect(d.heading).toContain('Not allowed in the current state');
    expect(d.text).toContain('already closed');
  });

  test('a finding with no remedy still tells the person to keep the ledger', () => {
    const o = classify(409, { detail: { error: 'anchor_contradicts_ledger', finding: 'x differs' } });
    if (o.kind !== 'conflict') throw new Error('expected a conflict');
    expect(describeOutcome(o).remedy).toMatch(/Keep the ledger and its attestation log/);
  });
});
