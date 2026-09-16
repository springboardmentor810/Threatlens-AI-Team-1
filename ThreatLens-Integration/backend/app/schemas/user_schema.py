from enum import Enum
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr


class UserRole(str, Enum):
    """
    The four platform roles.

    These exact strings travel in the JWT `role` claim and are compared
    verbatim by the other modules, so the vocabulary has to be shared:
      - app/alerts/router.py            _ALL_VIEW_ROLES / _UPDATE_ROLES / ...
      - frontend/src/constants/roles.ts ROLES / PAGE_ACCESS

    Both of those already used these snake_case names (as does section 4 of
    the project spec); only this enum disagreed, defining just two roles in
    title case ("Admin", "Security Analyst"). A token minted with the old
    values was rejected by every RBAC check in the alerts API.

    Display names belong in the frontend (ROLE_LABELS), not here.
    """

    SECURITY_ANALYST = "security_analyst"
    SOC_TEAM_MEMBER = "soc_team_member"
    ADMINISTRATOR = "administrator"
    RESEARCHER = "researcher"


# Register Request Schema
class UserCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    role: UserRole = UserRole.SECURITY_ANALYST


# Login Request Schema
class UserLogin(BaseModel):
    email: EmailStr
    password: str


# Profile Update Request Schema
class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    role: Optional[UserRole] = None


# User Response Schema
class UserResponse(BaseModel):
    id: int
    full_name: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# JWT Token Response Schema
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# JWT Token Payload Data Schema
class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None