"""Import third-party supply-chain documents as DRAFTS and supplier statements.

Two documents arrive from outside and neither is evidence about a machine until a person says so:

* a CycloneDX software bill of materials (SBOM) becomes a reviewable **draft** machine-software
  inventory (:mod:`assurance.ingest.sbom`). Nothing in an SBOM says which software a machine needs
  in order to operate safely, what its serial number is, or that anything was read off the unit;
  those are a named person's decisions, made through ``review_sbom_draft``, which enrols the
  machine through the one enrolment front door (:func:`assurance.machinery.enrol.enrol_machine`).
* a CSAF 2.0 advisory becomes a recorded **supplier advisory** (:mod:`assurance.ingest.csaf`)
  whose product statuses are matched against the enrolled fleet with an explicit result for every
  machine: ``affected``, ``under_investigation``, ``fixed``, ``not_affected`` or ``unknown``.
  A match that is not certain is ``unknown``, never a guess.

Both go through the same domain functions from the command line, the HTTP API and the MCP server.
"""

from __future__ import annotations
