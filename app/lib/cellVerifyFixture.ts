// The request body app/components/FirstCell.tsx sends to POST
// /v1/machine/verify — a real, honest, passing run, not hand-invented JSON.
//
// This is the exact output of tests/test_assurance_machine.py's own fixture
// builders (`envelope()` + `trace([sample(i) for i in range(5)])`, the same
// ones TestVerifyEndpoint._payload() uses), captured by actually calling
// `SafetyEnvelope.to_dict()` / `Trace.hashable_payload()` through the real
// classes in src/assurance/machine/{envelope,trace}.py and pasting the
// result verbatim — never retyped from memory. Regenerate it if those
// fixtures change:
//
//   PYTHONPATH=src python3 - <<'PY'
//   from datetime import UTC, datetime
//   from assurance.machine.envelope import (
//       FigureBasis, SafetyEnvelope, SensingUncertainty, StopPerformance, Workspace)
//   from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
//   MEASURED = FigureBasis(kind="measured", reference="STOP-TEST-1", date="2026-03-11")
//   env = SafetyEnvelope(
//       envelope_id="ENV-1", product="Cell", product_version="1.0.0",
//       workspace=Workspace(minimum=(-1000.0, -1000.0, 0.0), maximum=(1000.0, 1000.0, 2000.0)),
//       max_tcp_speed_mm_s={OperatingMode.SSM: 500.0, OperatingMode.AUTOMATIC: 2000.0,
//                           OperatingMode.STOPPED: 0.0, OperatingMode.PFL: 250.0},
//       stop=StopPerformance(reaction_time_s=0.1, stop_time_s=0.25, stop_distance_mm=120.0,
//                             measured_at_speed_mm_s=500.0, basis=MEASURED),
//       uncertainty=SensingUncertainty(human_position_mm=100.0, robot_position_mm=50.0, basis=MEASURED),
//       intrusion_distance_mm=850.0)
//   samples = [Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=500.0,
//                      mode=OperatingMode.SSM, separation=2000.0) for i in range(5)]
//   trace = Trace(trace_id="RUN-1", provenance=Provenance.FIELD, source_system="controller fw 1.0",
//                  started_at=datetime(2026, 9, 12, 4, 31, tzinfo=UTC), sample_rate_hz=50.0,
//                  samples=tuple(samples))
//   print(env.to_dict()); print(trace.hashable_payload())
//   PY
//
// This describes a 100ms-window recorded run under SSM at a constant 500mm/s
// with 2000mm separation the whole time — a clean pass against the declared
// envelope, tier VALIDATED, may_claim_physical_behaviour true (field
// provenance + measured stop figures). It is a stand-in run bundled with
// this page to prove the wire path end to end; the actor/role fields below
// are overridden with what the visitor typed in the form, everything else
// stays exactly as generated. A real integration posts the caller's own
// recorded trace, not this fixture.
export const CELL_VERIFY_FIXTURE = {
  envelope: {
    envelope_id: 'ENV-1',
    product: 'Cell',
    product_version: '1.0.0',
    workspace: {
      minimum: [-1000.0, -1000.0, 0.0],
      maximum: [1000.0, 1000.0, 2000.0],
      frame: 'cell',
    },
    max_tcp_speed_mm_s: {
      automatic: 2000.0,
      pfl: 250.0,
      ssm: 500.0,
      stopped: 0.0,
    },
    stop: {
      reaction_time_s: 0.1,
      stop_time_s: 0.25,
      stop_distance_mm: 120.0,
      measured_at_speed_mm_s: 500.0,
      basis: {
        kind: 'measured',
        reference: 'STOP-TEST-1',
        date: '2026-03-11',
      },
    },
    uncertainty: {
      human_position_mm: 100.0,
      robot_position_mm: 50.0,
      basis: {
        kind: 'measured',
        reference: 'STOP-TEST-1',
        date: '2026-03-11',
      },
    },
    intrusion_distance_mm: 850.0,
    human_approach_speed_mm_s: 1600.0,
    pfl_limits_hash: '',
    declared_by: {
      identifier: '',
      role: '',
      kind: 'person',
    },
    notes: '',
  },
  trace: {
    trace_id: 'RUN-1',
    provenance: 'field',
    source_system: 'controller fw 1.0',
    started_at: '2026-09-12T04:31:00Z',
    sample_rate_hz: 50.0,
    conditions: {},
    samples: [
      { t: 0.0, tcp: [0.0, 0.0, 1000.0], tcp_speed: 500.0, mode: 'ssm', separation: 2000.0, human_speed: null, contact_force: null, contact_area: null, body_region: '' },
      { t: 0.02, tcp: [0.0, 0.0, 1000.0], tcp_speed: 500.0, mode: 'ssm', separation: 2000.0, human_speed: null, contact_force: null, contact_area: null, body_region: '' },
      { t: 0.04, tcp: [0.0, 0.0, 1000.0], tcp_speed: 500.0, mode: 'ssm', separation: 2000.0, human_speed: null, contact_force: null, contact_area: null, body_region: '' },
      { t: 0.06, tcp: [0.0, 0.0, 1000.0], tcp_speed: 500.0, mode: 'ssm', separation: 2000.0, human_speed: null, contact_force: null, contact_area: null, body_region: '' },
      { t: 0.08, tcp: [0.0, 0.0, 1000.0], tcp_speed: 500.0, mode: 'ssm', separation: 2000.0, human_speed: null, contact_force: null, contact_area: null, body_region: '' },
    ],
  },
} as const;
