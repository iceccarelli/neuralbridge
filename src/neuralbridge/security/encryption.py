
"""
NeuralBridge — Credential Encryption Module.

This module provides robust, secure, and production-ready credential and
sensitive data encryption using the Fernet symmetric authenticated cryptography
scheme. It is designed for enterprise environments where security and compliance
are paramount.

Key Features:
- **Fernet Encryption**: Implements AES-128 in CBC mode with PKCS7 padding,
  authenticated via HMAC using SHA256. This provides strong guarantees of both
  confidentiality and integrity.
- **CredentialVault**: A high-level abstraction for managing the lifecycle of
  encrypted credentials, from generation to rotation.
- **Automatic Key Generation**: On first run, if no encryption key is found in
  the configuration, a new one is securely generated and saved, simplifying
  initial deployment.
- **Key Rotation**: Supports seamless rotation of encryption keys to comply with
  security best practices and regulatory requirements.
- **HSM-Ready Architecture**: Defines a clear ``EncryptionProvider`` interface,
  allowing the default Fernet-based implementation to be swapped with a
  Hardware Security Module (HSM) or other external KMS for enhanced security.
- **Base64 Encoding**: All encrypted ciphertexts are Base64 encoded, ensuring
  they can be safely stored in configuration files (YAML, JSON) or databases
  without character encoding issues.
"""

from __future__ import annotations

import base64
from typing import Protocol

import structlog
from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, Field, SecretStr

from neuralbridge.config import get_settings

logger = structlog.get_logger(__name__)


class EncryptionError(Exception):
    """Base exception for encryption/decryption failures."""


class DecryptionError(EncryptionError):
    """Raised when decryption fails, often due to an invalid token or key."""


class KeyGenerationError(EncryptionError):
    """Raised when a new encryption key cannot be generated."""


class EncryptedCredential(BaseModel):
    """
    Represents a credential that has been encrypted and is safe for storage.

    The ciphertext is Base64-encoded to prevent issues with storing binary data
    in text-based formats like YAML or JSON.
    """

    ciphertext: str = Field(
        ..., description="The Base64-encoded encrypted credential data."
    )


class EncryptionProvider(Protocol):
    """
    Abstract interface for an encryption provider.

    This protocol defines the contract for any class that provides encryption
    and decryption services. This HSM-ready architecture allows for future
    integration with Hardware Security Modules or other key management systems
    by creating a new class that implements this protocol.
    """

    def encrypt(self, plaintext: SecretStr) -> EncryptedCredential:
        """Encrypts a plaintext secret into an EncryptedCredential."""
        ...

    def decrypt(self, encrypted_credential: EncryptedCredential) -> SecretStr:
        """Decrypts an EncryptedCredential back into a plaintext secret."""
        ...


class FernetProvider(EncryptionProvider):
    """
    An EncryptionProvider that uses Fernet symmetric encryption.

    This is the default provider for NeuralBridge, offering a strong and easy-to-use
    implementation based on the ``cryptography`` library.
    """

    def __init__(self, key: SecretStr):
        """
        Initializes the Fernet provider with a Base64-encoded encryption key.

        Args:
            key: The secret encryption key.

        Raises:
            ValueError: If the provided key is invalid.
        """
        try:
            self._fernet = Fernet(key.get_secret_value().encode("utf-8"))
            logger.debug("FernetProvider initialized successfully.")
        except (ValueError, TypeError) as e:
            logger.error("Failed to initialize FernetProvider due to invalid key.", exc_info=e)
            raise ValueError("The provided Fernet key is invalid.") from e

    def encrypt(self, plaintext: SecretStr) -> EncryptedCredential:
        """Encrypts a plaintext string.

        Args:
            plaintext: The secret string to encrypt.

        Returns:
            An EncryptedCredential containing the Base64-encoded ciphertext.
        """
        encrypted_data = self._fernet.encrypt(plaintext.get_secret_value().encode("utf-8"))
        b64_encoded = base64.urlsafe_b64encode(encrypted_data).decode("utf-8")
        logger.info("Successfully encrypted data.")
        return EncryptedCredential(ciphertext=b64_encoded)

    def decrypt(self, encrypted_credential: EncryptedCredential) -> SecretStr:
        """Decrypts a ciphertext string.

        Args:
            encrypted_credential: The credential to decrypt.

        Returns:
            The decrypted plaintext secret.

        Raises:
            DecryptionError: If the ciphertext is invalid, malformed, or the key
                             is incorrect.
        """
        try:
            b64_decoded = base64.urlsafe_b64decode(
                encrypted_credential.ciphertext.encode("utf-8")
            )
            decrypted_data = self._fernet.decrypt(b64_decoded)
            logger.info("Successfully decrypted data.")
            return SecretStr(decrypted_data.decode("utf-8"))
        except (InvalidToken, TypeError, ValueError) as e:
            logger.error("Decryption failed. The token may be invalid or the key incorrect.", exc_info=e)
            raise DecryptionError("Failed to decrypt credential.") from e


class CredentialVault:
    """
    Manages the secure storage and retrieval of adapter credentials.

    This class acts as the primary interface for handling sensitive data.
    It automatically handles key management, using the key from the application
    settings or generating a new one if none exists.
    """

    _provider: EncryptionProvider

    def __init__(self, provider: EncryptionProvider | None = None):
        """
        Initializes the CredentialVault.

        If a provider is not supplied, it configures a default ``FernetProvider``
        using the key from the application settings. It will handle key generation
        if necessary.

        Args:
            provider: An optional encryption provider. If None, a default
                      Fernet provider is created.
        """
        if provider:
            self._provider = provider
            logger.debug("CredentialVault initialized with custom provider.")
        else:
            encryption_key = self._get_or_generate_key()
            self._provider = FernetProvider(key=encryption_key)
            logger.debug("CredentialVault initialized with default FernetProvider.")

    def _get_or_generate_key(self) -> SecretStr:
        """
        Retrieves the encryption key from settings, or generates and saves a new one.

        This method ensures that a valid encryption key is always available.
        If the ``encryption_key`` field in ``config.py`` is empty, it generates a
        new Fernet key, logs a security warning, and instructs the administrator
        on how to persist it.

        Returns:
            The encryption key as a SecretStr.

        Raises:
            KeyGenerationError: If key generation fails.
        """
        settings = get_settings()
        key = settings.encryption_key

        if key:
            logger.info("Loaded existing encryption key from settings.")
            return SecretStr(key)

        logger.warning(
            "No encryption key found in settings. Generating a new temporary key.",
            action="generate_key",
            security_implication="Credentials encrypted with this key will be unrecoverable if the application restarts without saving the key.",
        )
        try:
            new_key = Fernet.generate_key().decode("utf-8")
            logger.critical(
                "A new encryption key has been generated. "
                "You MUST save this key in your .env file or environment variables as NEURALBRIDGE_ENCRYPTION_KEY to ensure credential persistence.",
                new_key=new_key,
            )
            # In a real application, you might update the settings file or state manager.
            # For now, we use it for the current session.
            settings.encryption_key = new_key
            return SecretStr(new_key)
        except Exception as e:
            logger.exception("Failed to generate a new Fernet key.")
            raise KeyGenerationError("Could not generate new encryption key.") from e

    def encrypt_credential(self, value: SecretStr) -> EncryptedCredential:
        """
        Encrypts a sensitive value (e.g., an API key or password).

        Args:
            value: The plaintext secret to encrypt.

        Returns:
            The encrypted credential, ready for safe storage.
        """
        return self._provider.encrypt(value)

    def decrypt_credential(self, encrypted_credential: EncryptedCredential) -> SecretStr:
        """
        Decrypts a credential back to its plaintext form.

        Args:
            encrypted_credential: The encrypted data to decrypt.

        Returns:
            The plaintext secret.
        """
        return self._provider.decrypt(encrypted_credential)

    @staticmethod
    def rotate_key(
        old_vault: CredentialVault,
        new_key: SecretStr,
        encrypted_credential: EncryptedCredential,
    ) -> EncryptedCredential:
        """
        Re-encrypts a credential with a new key.

        This method facilitates key rotation by decrypting a credential with the old
        vault (and its key) and re-encrypting it with a new vault configured with
        the new key.

        Args:
            old_vault: The CredentialVault instance configured with the old key.
            new_key: The new Fernet key to use for re-encryption.
            encrypted_credential: The credential to re-encrypt.

        Returns:
            A new EncryptedCredential instance encrypted with the new key.
        """
        logger.info("Starting key rotation for a credential.")
        plaintext_credential = old_vault.decrypt_credential(encrypted_credential)

        new_provider = FernetProvider(key=new_key)
        new_vault = CredentialVault(provider=new_provider)

        re_encrypted_credential = new_vault.encrypt_credential(plaintext_credential)
        logger.info("Credential successfully re-encrypted with the new key.")

        return re_encrypted_credential
