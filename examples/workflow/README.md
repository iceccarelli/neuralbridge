# One machine, one change, evidence anyone can check

A synthetic walk through the workflow this product exists for. **Every name, hash, figure and
trace here is invented** — `DemoCo/AR-7#DEMO-0001` is not a real machine, and the "recorder" is a
key generated fresh on each run. Use it to see what you would receive; do not read it as evidence
about any equipment.

```bash
python examples/workflow/run.py          # each step, what it shows, what it does not show
python examples/workflow/run.py --json   # the same as one document; exit 0 only if all 12 steps agree
```

What happens, in order:

1. A recorder key is created and a **verifier's own trust list** names it.
2. The machine's declared configuration and two safety functions are sealed into a hash-chained ledger.
3. A recorded run is checked against the declared safety envelope; a trusted key signs the trace.
   Both functions read **covered at `validated`**.
4. A firmware update is recorded. Cover for both functions turns **stale** — the earlier run says
   nothing about the new firmware. (`machinery coverage` exits 1.)
5. A second run after the update is verified; cover returns.
6. The machine's whole position is sealed as a **passport**, and checked the way an outsider would:
   against the ledger, and by re-running the verification from the envelope and trace.

`tests/test_assurance_example_workflow.py` also edits the passport and the verification bundle,
swaps the trace, and checks with no trust list; each must be rejected or downgraded.

## What a green run does **not** show

- That any recorder, trace or envelope figure is physically true. A signature shows a trusted key
  signed those bytes.
- That the firmware update was safe, authorised, or the only change. Nothing here sees changes
  nobody recorded.
- That the function list is complete, or that anything meets a law or standard. The emergency-stop
  function is not in this pack because no trace check can demonstrate it.
- Who the people named are. Identities are declarations unless a signature binds them.
