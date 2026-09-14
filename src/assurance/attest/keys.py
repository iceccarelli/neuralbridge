"""The key that turns tamper-evidence into tamper-proof, and where it must not live.

A hash chain is tamper-*evident*: change a record and the links stop matching.
It is not tamper-*proof*, because whoever holds the database can rewrite every
link and produce a shorter, internally consistent history. The chain then
verifies perfectly and says nothing about what was removed.

The only defence is a value that left the building. Sign the head with a key the
operator of the ledger does not hold, keep the signatures, and a rewind stops
being deniable.

Which makes where the key lives the entire security property, and why
:meth:`SigningKey.save` refuses to write a private key into the directory
holding the ledger it signs. A key stored beside the thing it protects protects
nothing: whoever can rewrite the records can re-sign them. The refusal is not
paternalism — it is the difference between this being a security control and
being a decoration.

Ed25519 throughout: small keys, small signatures, no parameter choices to get
wrong, and no room for a curve or a padding mode to be selected badly.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError as _exc:  # pragma: no cover - environment, not logic
    raise ImportError(
        "assurance.attest needs the `cryptography` package for Ed25519. Install "
        "it with `pip install 'neuralbridge[assurance-attest]'` or "
        "`pip install cryptography`. This is the one runtime dependency in the "
        "assurance package, and it is here because writing a signature scheme by "
        "hand would be the worst decision in this repository."
    ) from _exc

from assurance.core.errors import AssuranceError

__all__ = ["SigningKeyError", "SigningKey", "VerifyingKey"]


class SigningKeyError(AssuranceError):
    """A key is missing, malformed, or being stored somewhere it must not be."""


def _fingerprint(public_bytes: bytes) -> str:
    """A short, stable name for a key, to print next to a signature.

    Sixteen hex characters of SHA-256 over the raw public key. Long enough that
    two keys in one organisation will not collide, short enough to read aloud
    over a telephone — which is how a public key actually gets confirmed
    between two companies that do not already trust each other's email.
    """
    return hashlib.sha256(public_bytes).hexdigest()[:16]


@dataclass(frozen=True)
class VerifyingKey:
    """The half anybody may hold. Verification needs nothing else."""

    public: ed25519.Ed25519PublicKey

    @classmethod
    def from_pem(cls, text: str | bytes) -> VerifyingKey:
        data = text.encode("utf-8") if isinstance(text, str) else text
        try:
            key = serialization.load_pem_public_key(data)
        except (ValueError, TypeError) as exc:
            raise SigningKeyError(f"not a readable PEM public key: {exc}") from exc
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise SigningKeyError(
                "this is not an Ed25519 public key. Attestations are Ed25519 only, "
                "so that there is no algorithm or parameter for anybody to get wrong."
            )
        return cls(public=key)

    @classmethod
    def from_file(cls, path: str | Path) -> VerifyingKey:
        p = Path(path)
        if not p.exists():
            raise SigningKeyError(
                f"{p} does not exist. A verifier needs the public key from a channel "
                "that is not the same one the attestations arrived on; a signature "
                "checked against a key that came with it proves nothing."
            )
        return cls.from_pem(p.read_bytes())

    def raw_bytes(self) -> bytes:
        raw: bytes = self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw

    def pem(self) -> str:
        encoded: bytes = self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return encoded.decode("ascii")

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.raw_bytes())

    def verify(self, message: bytes, signature: bytes) -> bool:
        """True only for a signature this key made over exactly these bytes."""
        try:
            self.public.verify(signature, message)
        except InvalidSignature:
            return False
        return True


@dataclass(frozen=True)
class SigningKey:
    """The half that must live somewhere the ledger's operator cannot reach."""

    private: ed25519.Ed25519PrivateKey

    @classmethod
    def generate(cls) -> SigningKey:
        return cls(private=ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, text: str | bytes, *, passphrase: str = "",
                 where: str = "the supplied key") -> SigningKey:
        """Load from PEM bytes. This is how a secrets manager hands over a key."""
        data = text.encode("utf-8") if isinstance(text, str) else text
        try:
            key = serialization.load_pem_private_key(
                data, password=passphrase.encode("utf-8") if passphrase else None
            )
        except TypeError as exc:
            raise SigningKeyError(
                f"{where} is encrypted and no passphrase was given."
            ) from exc
        except ValueError as exc:
            raise SigningKeyError(
                f"{where} could not be read: {exc}. If it is encrypted, the "
                "passphrase is wrong."
            ) from exc
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise SigningKeyError(f"{where} is not an Ed25519 private key.")
        return cls(private=key)

    @classmethod
    def load(cls, path: str | Path, *, passphrase: str = "") -> SigningKey:
        p = Path(path)
        if not p.exists():
            raise SigningKeyError(f"{p} does not exist.")
        return cls.from_pem(p.read_bytes(), passphrase=passphrase, where=str(p))

    def save(
        self, path: str | Path, *, passphrase: str = "", ledger: str | Path | None = None,
    ) -> Path:
        """Write the private key, refusing the one place it must never go.

        ``ledger`` is the ledger this key will sign. When it is given and the
        key would land in the same directory, the write is refused: a signing
        key stored beside the records it signs is not a control, because
        whoever can rewrite the records can re-sign them.
        """
        p = Path(path).resolve()
        if p.exists():
            raise SigningKeyError(
                f"{p} already exists. Refusing to overwrite a signing key: every "
                "attestation ever made with the old one becomes unverifiable, and "
                "that is indistinguishable from the old one being repudiated."
            )
        if ledger is not None:
            led = Path(ledger).resolve()
            if p.parent == led.parent:
                raise SigningKeyError(
                    f"refusing to write the signing key into {p.parent}, which is "
                    f"where {led.name} lives. The whole value of an attestation is "
                    "that the key is somewhere the ledger's operator is not. Put it "
                    "on a token, in a secrets manager, or on another machine."
                )
        if not passphrase:
            # Not refused: an unattended signer in a locked-down secrets store is
            # a legitimate deployment, and forcing a passphrase there produces a
            # passphrase in an environment variable, which is worse.
            encryption: serialization.KeySerializationEncryption = (
                serialization.NoEncryption())
        else:
            encryption = serialization.BestAvailableEncryption(
                passphrase.encode("utf-8"))

        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(self.private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        ))
        p.chmod(0o600)
        return p

    @property
    def verifying(self) -> VerifyingKey:
        return VerifyingKey(public=self.private.public_key())

    @property
    def fingerprint(self) -> str:
        return self.verifying.fingerprint

    def sign(self, message: bytes) -> bytes:
        signature: bytes = self.private.sign(message)
        return signature
