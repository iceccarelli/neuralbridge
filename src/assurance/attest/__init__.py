"""Signed head attestations: the part a rewind cannot reach.

    keys         Ed25519, and the refusal to store the key beside the ledger
    attestation  sign the head, refuse the cases that would lie, verify the log

A hash chain proves nothing was *edited*. Only a signature made by a key the
database's holder does not have proves nothing was *removed*.
"""

from assurance.attest.attestation import (
    ATTESTATION_FORMAT,
    AttestationBasis,
    AttestationError,
    AttestationLog,
    HeadAttestation,
    LedgerHead,
    LogVerdict,
    attest,
    head_of,
    verify_log,
)
from assurance.attest.keys import SigningKey, SigningKeyError, VerifyingKey

__all__ = [
    "ATTESTATION_FORMAT",
    "AttestationBasis",
    "AttestationError",
    "AttestationLog",
    "HeadAttestation",
    "SigningKeyError",
    "LedgerHead",
    "LogVerdict",
    "SigningKey",
    "VerifyingKey",
    "attest",
    "head_of",
    "verify_log",
]
