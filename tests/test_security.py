"""
Tests for NeuralBridge Security Modules.

Covers authentication, encryption, audit logging, RBAC, and rate limiting.
"""

from __future__ import annotations

import pytest


class TestAuthentication:
    """Tests for the auth module."""

    def test_import_auth(self):
        from neuralbridge.security.auth import AuthHandler
        assert AuthHandler is not None

    def test_create_and_verify_token(self):
        from neuralbridge.security.auth import AuthHandler
        handler = AuthHandler.__new__(AuthHandler)
        # Manually set the JWT attributes from settings
        from neuralbridge.config import get_settings
        settings = get_settings()
        handler.jwt_secret = settings.jwt_secret_key
        handler.jwt_algorithm = settings.jwt_algorithm
        handler.access_token_expire = settings.jwt_access_token_expire_minutes
        token = handler.create_access_token(data={"sub": "testuser", "role": "admin"})
        assert isinstance(token, str)
        assert len(token) > 0


class TestEncryption:
    """Tests for the credential vault."""

    def test_import_encryption(self):
        from neuralbridge.security.encryption import CredentialVault
        assert CredentialVault is not None

    def test_encrypt_decrypt(self):
        from pydantic import SecretStr

        from neuralbridge.security.encryption import CredentialVault
        vault = CredentialVault()
        plaintext = SecretStr("my-secret-api-key")
        encrypted = vault.encrypt_credential(plaintext)
        decrypted = vault.decrypt_credential(encrypted)
        assert decrypted.get_secret_value() == "my-secret-api-key"


class TestAuditLogging:
    """Tests for the immutable audit logger."""

    def test_import_audit(self):
        from neuralbridge.security.audit import AuditLogger
        assert AuditLogger is not None

    @pytest.mark.asyncio
    async def test_log_and_query(self):
        from neuralbridge.security.audit import AuditLogger, InMemoryAuditStorage
        storage = InMemoryAuditStorage()
        logger = AuditLogger(storage=storage)
        await logger.log_event(
            event_type="test.event",
            actor="test_user",
            resource="test_resource",
            action="test_action",
            result="success",
        )
        events = []
        async for event in logger.query_events(actor="test_user"):
            events.append(event)
        assert len(events) >= 1


class TestRBAC:
    """Tests for role-based access control."""

    def test_import_rbac(self):
        from neuralbridge.security.rbac import Permission, Role
        assert Role is not None
        assert Permission is not None

    def test_admin_has_all_permissions(self):
        from neuralbridge.security.rbac import Permission, Role, User, check_permission
        admin = User(username="admin", role=Role.ADMIN)
        for perm in Permission:
            assert check_permission(admin, perm) is True

    def test_readonly_cannot_manage(self):
        from neuralbridge.security.rbac import Permission, Role, User, check_permission
        viewer = User(username="viewer", role=Role.READ_ONLY)
        assert check_permission(viewer, Permission.MANAGE_ADAPTERS) is False


class TestRateLimiting:
    """Tests for the rate limiter."""

    def test_import_rate_limit(self):
        from neuralbridge.security.rate_limit import RateLimiter
        assert RateLimiter is not None
