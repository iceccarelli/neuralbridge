"""
NeuralBridge: Role-Based Access Control (RBAC) System.

This module provides a flexible and robust RBAC system for the NeuralBridge
enterprise middleware. It defines roles, permissions, and policies to control
access to various resources and operations within the application.

The implementation includes:
- Role Enum: Defines the default user roles.
- Permission Enum: Defines granular permissions for specific actions.
- RBACPolicy Class: Maps roles to their allowed permissions.
- check_permission(): Verify if a user's role grants a specific permission.
- require_role(): A FastAPI dependency decorator to protect endpoints.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from functools import wraps
from typing import Any

import structlog
from fastapi import Depends, HTTPException, status
from pydantic import BaseModel

logger = structlog.get_logger(__name__)


class User(BaseModel):
    """A mock user model for demonstration purposes."""

    username: str
    role: Role


class Role(StrEnum):
    """Enumeration of user roles within the NeuralBridge system.

    Each role corresponds to a set of permissions defined in the
    ``RBACPolicy``.
    """

    ADMIN = "Admin"
    COMPLIANCE_OFFICER = "ComplianceOfficer"
    DEVELOPER = "Developer"
    READ_ONLY = "ReadOnly"


class Permission(StrEnum):
    """Enumeration of granular permissions for actions within NeuralBridge.

    Permissions are the fundamental units of access control, granted to
    roles.
    """

    MANAGE_ADAPTERS = "manage_adapters"
    EXECUTE_OPERATIONS = "execute_operations"
    VIEW_LOGS = "view_logs"
    MANAGE_COMPLIANCE = "manage_compliance"
    MANAGE_USERS = "manage_users"
    VIEW_DASHBOARD = "view_dashboard"


class RBACPolicy:
    """Defines the mapping of roles to their granted permissions.

    This class acts as the single source of truth for the RBAC policy.
    It is designed to be easily readable and modifiable to adjust access
    control policies as the application evolves.
    """

    _policies: dict[Role, set[Permission]] = {
        Role.ADMIN: {
            Permission.MANAGE_ADAPTERS,
            Permission.EXECUTE_OPERATIONS,
            Permission.VIEW_LOGS,
            Permission.MANAGE_COMPLIANCE,
            Permission.MANAGE_USERS,
            Permission.VIEW_DASHBOARD,
        },
        Role.COMPLIANCE_OFFICER: {
            Permission.VIEW_LOGS,
            Permission.MANAGE_COMPLIANCE,
            Permission.VIEW_DASHBOARD,
        },
        Role.DEVELOPER: {
            Permission.MANAGE_ADAPTERS,
            Permission.EXECUTE_OPERATIONS,
            Permission.VIEW_LOGS,
            Permission.VIEW_DASHBOARD,
        },
        Role.READ_ONLY: {
            Permission.VIEW_LOGS,
            Permission.VIEW_DASHBOARD,
        },
    }

    @classmethod
    def get_permissions(cls, role: Role) -> set[Permission]:
        """Retrieve the set of permissions for a given role.

        Args:
            role: The role for which to retrieve permissions.

        Returns:
            A set of permissions granted to the role.
        """
        return cls._policies.get(role, set())


# Update the User model to use the now-defined Role enum.
User.model_rebuild()


def check_permission(user: User, permission: Permission) -> bool:
    """Check if a user has a specific permission based on their role.

    This function is the core of the permission checking logic. It fetches
    the permissions for the user's role from the ``RBACPolicy`` and checks
    if the required permission is present.

    Args:
        user: The user object, containing their role.
        permission: The permission to check for.

    Returns:
        True if the user has the permission, False otherwise.
    """
    if not isinstance(user, User) or not hasattr(user, "role"):
        logger.warning(
            "Invalid user object provided to check_permission.",
        )
        return False

    user_permissions = RBACPolicy.get_permissions(user.role)
    has_permission = permission in user_permissions

    logger.debug(
        "Permission check result",
        user=user.username,
        role=user.role,
        required_permission=permission,
        has_permission=has_permission,
    )

    return has_permission


async def get_current_user() -> User:
    """Mock FastAPI dependency to get the current user.

    In a real application, this would decode a JWT from the request
    header, fetch the user from the database, and return the user object.
    Here, we return a mock 'Admin' user for demonstration.
    """
    logger.info("Using mock 'Admin' user for demonstration.")
    return User(username="mockadmin", role=Role.ADMIN)


def require_role(*roles: Role) -> Callable[..., Any]:
    """FastAPI dependency decorator to enforce role-based access.

    This decorator ensures that only users with one of the specified
    roles can access the decorated endpoint. If the user does not have
    the required role, an HTTPException with a 403 Forbidden status is
    raised.

    Args:
        *roles: A list of roles that are allowed to access the endpoint.

    Returns:
        A decorator function that can be used with FastAPI dependencies.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def wrapper(
            *args: Any,
            current_user: User = Depends(get_current_user),
            **kwargs: Any,
        ) -> Any:
            if current_user.role not in roles:
                logger.warning(
                    "Access denied for user",
                    user=current_user.username,
                    user_role=current_user.role,
                    required_roles=[r.value for r in roles],
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "You do not have the necessary permissions "
                        "to access this resource."
                    ),
                )
            return await func(
                *args, current_user=current_user, **kwargs,
            )

        return wrapper

    return decorator
