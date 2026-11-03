// What share of the fleet has evidence, verification, an intel match and an attested anchor.
// Pure functions over answers the API already gave; nothing here is fetched or invented.
//
// One rule runs through all of it: a value that is missing is UNKNOWN. It is never counted as
// covered and never as zero. A source that has not answered makes every machine UNKNOWN on the
// dimension it feeds, and an empty fleet has no coverage to report (0 of 0 is not "clear").

import type { AttestLog, CaseQueue, Fleet, Value, ValueMachine } from './assuranceApi';

export type Dimension = 'evidence' | 'verification' | 'intel' | 'anchor';
export const DIMENSIONS: Dimension[] = ['evidence', 'verification', 'intel', 'anchor'];

// covered: shown on records. partial: some of it. none: the records say it is absent.
// unknown: the records, or the source, do not say.
export type State = 'covered' | 'partial' | 'none' | 'unknown';
export type Cell = { state: State; reason: string };

export type Source<T> = { status: 'ok'; data: T } | { status: 'loading' } | { status: 'unavailable'; reason: string };

export type CoverageInput = {
  fleet: Fleet;
  value: Source<Value>;
  cases: Source<CaseQueue>;
  attest: Source<AttestLog>;
};

export type MachineCoverage = {
  machine: string;
  site: string;
  configuration_hash: string | null;
  cells: Record<Dimension, Cell>;
};

export type Tally = { covered: number; partial: number; none: number; unknown: number; denominator: number };

export type CoverageReport = {
  /** Machines the fleet answer lists, the denominator of every machine count. */
  machines: MachineCoverage[];
  tally: Record<Dimension, Tally>;
  /** Distinct configuration hashes among those machines, and the same tallies over them. */
  configurations: { denominator: number; unhashed_machines: number; tally: Record<Dimension, Tally> };
  /** Safety functions: verification counted per function, from /v1/value. Null when unknown. */
  functions: { current: number; total: number; machines_without_figures: number } | null;
  empty: boolean;
  chain_verified: boolean;
};

const NON_CURRENT = ['failing', 'stale', 'unchecked', 'incomplete', 'never_verified', 'not_demonstrable'];

function unknownCell(reason: string): Cell {
  return { state: 'unknown', reason };
}

function sourceReason<T>(name: string, src: Source<T>): string {
  if (src.status === 'loading') return `${name} has not answered yet`;
  if (src.status === 'unavailable') return `${name} unavailable: ${src.reason}`;
  return '';
}

function evidenceCell(v: ValueMachine | undefined): Cell {
  if (!v) return unknownCell('this machine is not in the position answer; what is installed is not known');
  if (!v.manifest) return { state: 'none', reason: 'no sealed manifest: what is installed is unknown' };
  if (v.manifest.collection_incomplete) {
    return { state: 'partial', reason: 'the newest manifest records an incomplete collection; items not read are unknown' };
  }
  const inv = v.inventory;
  if (!inv || inv.items === 0) return { state: 'none', reason: 'the manifest lists no items' };
  if (inv.read_from_machine === inv.items) {
    return { state: 'covered', reason: `${inv.items} of ${inv.items} item(s) hashed off the unit` };
  }
  return {
    state: 'partial',
    reason: `${inv.read_from_machine} of ${inv.items} item(s) hashed off the unit; ${inv.supplied_by_vendor} from a vendor file, ${inv.declared_only} declared with no hash`,
  };
}

function verificationCell(v: ValueMachine | undefined, verdict: string | undefined): Cell {
  if (!v) return unknownCell('this machine is not in the position answer; no verification figures');
  if (!v.manifest || !v.coverage) return { state: 'none', reason: 'no sealed manifest, so no safety function to verify against' };
  const total = v.coverage.functions;
  if (total === 0) return unknownCell('no safety function is declared; nothing can be said to be verified');
  const current = v.coverage.current ?? 0;
  const gaps = NON_CURRENT.filter((k) => (v.coverage?.[k] ?? 0) > 0)
    .map((k) => `${v.coverage?.[k]} ${k.replace('_', ' ')}`)
    .join(', ');
  if (current === 0) return { state: 'none', reason: `0 of ${total} function(s) current (${gaps || 'no state reported'})` };
  if (current < total) return { state: 'partial', reason: `${current} of ${total} function(s) current (${gaps})` };
  if (verdict === 'covered_at_community') {
    return { state: 'partial', reason: `${total} of ${total} current, but only on evidence below validated` };
  }
  return { state: 'covered', reason: `${total} of ${total} function(s) current` };
}

function intelCell(machine: string, cases: Source<CaseQueue>): Cell {
  if (cases.status !== 'ok') return unknownCell(sourceReason('the case queue', cases));
  const hit = cases.data.cases.filter((c) => c.trigger === 'supplier_advisory' && c.machines.includes(machine));
  if (hit.length > 0) {
    return {
      state: 'covered',
      reason: `named by supplier-advisory case(s) ${hit.map((c) => c.case_id).join(', ')}: a match is recorded, a person decides what it means`,
    };
  }
  return unknownCell('no advisory or intel match is recorded for this machine; that is not a finding of no match');
}

function manifestSeq(machine: string, value: Source<Value>): number | null {
  if (value.status !== 'ok') return null;
  for (const f of value.data.findings ?? []) {
    if (f.machine !== machine) continue;
    for (const r of f.refs) if (typeof r.seq === 'number') return r.seq;
  }
  return null;
}

/** The newest attestation the operator's signer read from the ledger itself, or null. */
export function latestAnchor(log: AttestLog) {
  const read = log.attestations.filter((a) => a.basis === 'read_from_ledger');
  if (read.length === 0) return null;
  return read.reduce((a, b) => (b.head_seq > a.head_seq ? b : a));
}

function anchorCell(machine: string, value: Source<Value>, attest: Source<AttestLog>): Cell {
  if (attest.status !== 'ok') return unknownCell(sourceReason('the attestation log', attest));
  const anchor = latestAnchor(attest.data);
  if (!anchor) {
    const declared = attest.data.attestations.length;
    return {
      state: 'none',
      reason: declared
        ? `${declared} attestation(s) are declared by the holder; none was read from this ledger by the operator, so no anchor`
        : 'no attestation has been read from this ledger by the operator, so no anchor',
    };
  }
  const seq = manifestSeq(machine, value);
  if (seq === null) {
    return unknownCell('the ledger position of this machine’s record is not stated, so it cannot be placed against the anchor');
  }
  if (seq <= anchor.head_seq) {
    return {
      state: 'covered',
      reason: `record #${seq} is at or before the anchored head #${anchor.head_seq} (signed ${anchor.attested_at}); signature not checked here`,
    };
  }
  return { state: 'none', reason: `record #${seq} is after the latest anchored head #${anchor.head_seq}: no signature covers it` };
}

function tally(cells: State[], denominator: number): Tally {
  const t: Tally = { covered: 0, partial: 0, none: 0, unknown: 0, denominator };
  for (const s of cells) t[s]++;
  return t;
}

/** A configuration is covered only when every machine on it is; unknown when no gap is known. */
export function combine(states: State[]): State {
  if (states.length === 0) return 'unknown';
  if (states.every((s) => s === 'covered')) return 'covered';
  if (states.every((s) => s === 'none')) return 'none';
  if (states.some((s) => s === 'none' || s === 'partial')) return 'partial';
  return 'unknown';
}

export function computeCoverage(input: CoverageInput): CoverageReport {
  const { fleet, value, cases, attest } = input;
  const chainOk = fleet.chain_verified && (value.status !== 'ok' || value.data.ledger.chain_verified);
  const byName = new Map<string, ValueMachine>();
  if (value.status === 'ok') for (const m of value.data.machines) byName.set(m.machine, m);

  const machines: MachineCoverage[] = fleet.machines.map((row) => {
    let cells: Record<Dimension, Cell>;
    if (!chainOk) {
      const r = 'the ledger chain does not verify, so nothing drawn from it is offered';
      cells = { evidence: unknownCell(r), verification: unknownCell(r), intel: unknownCell(r), anchor: unknownCell(r) };
    } else {
      const v = byName.get(row.machine);
      const missing = value.status === 'ok' ? null : unknownCell(sourceReason('the position answer', value));
      cells = {
        evidence: missing ?? evidenceCell(v),
        verification: missing ?? verificationCell(v, row.verdict),
        intel: intelCell(row.machine, cases),
        anchor: anchorCell(row.machine, value, attest),
      };
      if (value.status === 'ok' && value.data.withheld) {
        cells.evidence = unknownCell(value.data.withheld);
        cells.verification = unknownCell(value.data.withheld);
      }
    }
    return { machine: row.machine, site: row.site, configuration_hash: row.configuration_hash || null, cells };
  });

  const n = machines.length;
  const tallies = {} as Record<Dimension, Tally>;
  const cfgTallies = {} as Record<Dimension, Tally>;
  const groups = new Map<string, MachineCoverage[]>();
  let unhashed = 0;
  for (const m of machines) {
    if (!m.configuration_hash) unhashed++;
    else groups.set(m.configuration_hash, [...(groups.get(m.configuration_hash) ?? []), m]);
  }
  for (const d of DIMENSIONS) {
    tallies[d] = tally(machines.map((m) => m.cells[d].state), n);
    cfgTallies[d] = tally([...groups.values()].map((g) => combine(g.map((m) => m.cells[d].state))), groups.size);
  }

  let functions: CoverageReport['functions'] = null;
  if (chainOk && value.status === 'ok' && !value.data.withheld) {
    let current = 0;
    let total = 0;
    let without = 0;
    for (const m of machines) {
      const c = byName.get(m.machine)?.coverage;
      if (!c) without++;
      else {
        total += c.functions;
        current += c.current ?? 0;
      }
    }
    functions = { current, total, machines_without_figures: without };
  }

  return {
    machines,
    tally: tallies,
    configurations: { denominator: groups.size, unhashed_machines: unhashed, tally: cfgTallies },
    functions,
    empty: n === 0,
    chain_verified: chainOk,
  };
}

/** "3 of 10 (30%)" only when the denominator is real; otherwise it says the share is not defined. */
export function shareText(count: number, denominator: number): string {
  if (denominator <= 0) return 'not defined (0 machines)';
  return `${count} of ${denominator} (${Math.round((count / denominator) * 100)}%)`;
}
