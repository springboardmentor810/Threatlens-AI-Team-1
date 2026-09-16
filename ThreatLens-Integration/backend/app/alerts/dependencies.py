"""
Auth/RBAC dependencies for the Alert & Notification Module.

Replaces the module's former `auth_stub.py`, which decoded the JWT itself
because Member 1's auth module did not exist when the alerts module was
written. It does not decode anything now: authentication goes through
`app.middleware.auth_middleware.get_current_user`, the same dependency the
rest of the platform uses.

That matters for more than tidiness. The stub trusted any correctly signed
token, so a deleted or deactivated account kept working until its token
expired. The real dependency loads the user from the database on every
request and rejects inactive accounts.

`CurrentUser` is kept as the value the router and service see, so neither had
to change shape. It is projected from the ORM `User`:

    user_id  <- user.email

`user_id` is the email because that is what /auth/login puts in the token's
`sub` claim, and `Alert.recipient_user_id` is matched against it when scoping
a researcher to their own alerts.

KNOWN LIMITATION: email is mutable (PUT /auth/profile can change it), so a
researcher who changes their address stops matching alerts already addressed
to the old one. The durable fix is to key `Alert.recipient_user_id` on the
immutable `users.id` and have whoever raises an alert resolve the recipient to
that id; it needs a data migration and agreement with Members 5 and 7, so it
is deliberately not done here.
"""

from typing import Iterable

from fastapi import Depends, HTTPException, status
from pydantic import BaseModel

from app.alerts.config import settings
from app.middleware.auth_middleware import get_current_user as _get_authenticated_user
from app.models.user import User


class CurrentUser(BaseModel):
    user_id: str
    role: str
    email: str | None = None


def _to_current_user(user: User) -> CurrentUser:
    return CurrentUser(user_id=user.email, role=user.role, email=user.email)


def get_current_user(user: User = Depends(_get_authenticated_user)) -> CurrentUser:
    """Authenticated caller, projected onto the shape this module expects."""
    return _to_current_user(user)


def require_roles(allowed_roles: Iterable[str]):
    """Dependency factory: raises 403 if current_user.role isn't in allowed_roles."""

    allowed = set(allowed_roles)

    def _check(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current_user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )
        return current_user

    return _check


def verify_internal_api_key(x_internal_api_key: str | None) -> None:
    """
    Used only by the service-to-service /ingest endpoint (Member 5 -> Member 6).

    Deliberately kept: this path has no logged-in user, so Member 1's auth
    module has no equivalent. Not a substitute for real service auth -- see
    config.py.
    """
    if not x_internal_api_key or x_internal_api_key != settings.alert_ingest_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing internal service API key.",
        )
