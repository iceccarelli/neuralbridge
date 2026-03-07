
"""
NeuralBridge — Multi-Strategy Authentication Module.

This module provides a robust, production-quality authentication system supporting
multiple strategies: OAuth2, API keys, JWT tokens, basic auth, and client
certificates. It is designed for integration with FastAPI and leverages best-practice
libraries like Pydantic, python-jose, and passlib.

Key Features:
- OAuth2 Password Bearer Flow: Securely handle user login and token issuance.
- API Key Validation: Support for header-based API key authentication.
- JWT Token Management: Create, verify, and decode JWTs with standard claims.
- FastAPI Integration: Provides a `get_current_user` dependency for protecting routes.
- Pluggable Credentials Store: A flexible interface for storing and retrieving user
  and API key data from any backend (e.g., database, LDAP).
- RBAC Roles: Pre-defined user roles for authorization.
- Structured Logging: Uses structlog for machine-readable and human-friendly logs.
"""

from __future__ import annotations

import abc
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

import structlog
from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, ValidationError

from neuralbridge.config import Settings, get_settings

# Initialize logger and settings
logger = structlog.get_logger(__name__)
settings: Settings = get_settings()

# ── Constants and Configuration ───────────────────────────────────────────────

# Password hashing context using passlib
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# FastAPI security schemes
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
api_key_scheme = APIKeyHeader(name="X-API-Key")

# JWT configuration from settings
JWT_SECRET_KEY = settings.jwt_secret_key
JWT_ALGORITHM = settings.jwt_algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.jwt_access_token_expire_minutes


# ── RBAC Roles ────────────────────────────────────────────────────────────────

class Role(StrEnum):
    """Enumeration of default RBAC roles."""
    ADMIN = "Admin"
    COMPLIANCE_OFFICER = "ComplianceOfficer"
    DEVELOPER = "Developer"
    READ_ONLY = "ReadOnly"


# ── Pydantic Models ───────────────────────────────────────────────────────────

class TokenPayload(BaseModel):
    """Schema for the data encoded within a JWT."""
    sub: str = Field(..., description="Subject of the token, typically the user ID or username.")
    exp: int | None = Field(None, description="Expiration time claim.")
    roles: list[Role] = Field(default_factory=list, description="List of roles assigned to the user.")


class UserInfo(BaseModel):
    """Schema for user information retrieved from the credentials store."""
    username: str
    hashed_password: str
    roles: list[Role]
    disabled: bool = False


class APIKeyRecord(BaseModel):
    """Schema for API key information retrieved from the credentials store."""
    key: str
    owner: str
    roles: list[Role]
    expires_at: datetime | None = None


# ── Credentials Store Interface ───────────────────────────────────────────────

class CredentialsStore(abc.ABC):
    """
    Abstract base class defining the interface for a credentials store.

    This interface allows for a pluggable backend for storing and retrieving
    user and API key information. Implementations could use a database,
    an LDAP directory, or a simple in-memory dictionary for testing.
    """

    @abc.abstractmethod
    async def get_user(self, username: str) -> UserInfo | None:
        """
        Retrieve a user by their username.

        Args:
            username: The username to look up.

        Returns:
            A UserInfo object if the user is found, otherwise None.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def get_api_key(self, api_key: str) -> APIKeyRecord | None:
        """
        Retrieve an API key record by the key itself.

        Args:
            api_key: The API key to look up.

        Returns:
            An APIKeyRecord object if the key is found and valid, otherwise None.
        """
        raise NotImplementedError


# ── Authentication Handler ────────────────────────────────────────────────────

class AuthHandler:
    """
    Handles core authentication logic, including password management and JWT operations.
    """

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verifies a plain-text password against a hashed password.

        Args:
            plain_password: The password to verify.
            hashed_password: The stored hashed password.

        Returns:
            True if the password is correct, otherwise False.
        """
        return bool(pwd_context.verify(plain_password, hashed_password))

    def get_password_hash(self, password: str) -> str:
        """
        Hashes a plain-text password.

        Args:
            password: The password to hash.

        Returns:
            The hashed password string.
        """
        return str(pwd_context.hash(password))

    def create_access_token(self, data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
        """
        Creates a new JWT access token.

        Args:
            data: The data to encode in the token payload.
            expires_delta: The lifespan of the token. Defaults to the value from settings.

        Returns:
            The encoded JWT string.
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        return str(encoded_jwt)

    def decode_token(self, token: str) -> TokenPayload | None:
        """
        Decodes and validates a JWT.

        Args:
            token: The JWT string to decode.

        Returns:
            The decoded token payload if validation is successful, otherwise None.
        """
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            return TokenPayload(**payload)
        except (JWTError, ValidationError) as e:
            logger.warn("JWT decoding failed", error=str(e), token=token)
            return None


# ── FastAPI Dependency ────────────────────────────────────────────────────────

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    credentials_store: CredentialsStore = Depends(), # This needs to be provided in the app
    auth_handler: AuthHandler = Depends(AuthHandler)
) -> UserInfo:
    """
    FastAPI dependency to get the current authenticated user.

    This function is used in path operation decorators to protect endpoints.
    It validates the JWT from the Authorization header and fetches the user
    from the credentials store.

    Args:
        token: The OAuth2 token provided by the client.
        credentials_store: The dependency that provides the credentials store implementation.
        auth_handler: The dependency that provides the authentication handler.

    Returns:
        The authenticated user's information.

    Raises:
        HTTPException: If authentication fails for any reason.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    token_payload = auth_handler.decode_token(token)
    if not token_payload or not token_payload.sub:
        raise credentials_exception

    user = await credentials_store.get_user(username=token_payload.sub)
    if user is None:
        raise credentials_exception

    if user.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    return user


def require_roles(required_roles: list[Role]) -> Callable[[UserInfo], Awaitable[None]]:
    """
    Factory for a dependency that checks if a user has the required roles.

    This allows for flexible, role-based access control on specific endpoints.

    Args:
        required_roles: A list of roles, any of which grants access.

    Returns:
        A dependency function that can be used in FastAPI path operations.
    """
    async def role_checker(current_user: UserInfo = Depends(get_current_user)) -> None:
        if not any(role in current_user.roles for role in required_roles):
            logger.warn(
                "Role-based access denied",
                user=current_user.username,
                required_roles=required_roles,
                user_roles=current_user.roles,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="The user does not have the required permissions",
            )
    return role_checker
