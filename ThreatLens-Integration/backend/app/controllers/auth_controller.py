import logging
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.config import settings
from app.alerts.config import settings as alert_settings
from app.alerts.email_service import send_email
from app.auth.jwt_handler import create_reset_token, decode_reset_token
from app.auth.security import hash_password
from app.database.database import get_db
from app.models.user import User
from app.repositories.user_repository import get_user_by_email
from app.schemas.user_schema import (
    UserCreate,
    UserSignup,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    UserLogin,
    UserUpdate,
    UserResponse,
    Token,
    UserRole
)
from app.services.auth_service import (
    register_user,
    login_user,
    get_user_profile,
    update_user_profile,
    delete_user_profile
)
from app.middleware.auth_middleware import (
    get_current_user,
    RoleChecker
)

logger = logging.getLogger("auth.controller")

router = APIRouter(
    # Every router sits under /api/v1 so the frontend has one base path
    # (axiosInstance baseURL). This moved from "/auth" during integration.
    prefix="/api/v1/auth",
    tags=["Authentication"]
)


# --------------------------------------------------
# SIGNUP (Public self-service, always security_analyst)
# --------------------------------------------------

@router.post(
    "/signup",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Self-service user registration",
)
def signup(
    user: UserSignup,
    db: Session = Depends(get_db)
):
    create_payload = UserCreate(
        full_name=user.full_name,
        email=user.email,
        password=user.password,
        role=UserRole.SECURITY_ANALYST,
    )
    new_user = register_user(db, create_payload)

    if not new_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists"
        )

    return new_user


# --------------------------------------------------
# REGISTER (Admin-only with selectable role)
# --------------------------------------------------

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(RoleChecker([UserRole.ADMINISTRATOR]))
    ],
    summary="Admin-only user registration",
)
def register(
    user: UserCreate,
    db: Session = Depends(get_db)
):
    new_user = register_user(db, user)

    if not new_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists"
        )

    return new_user


# --------------------------------------------------
# FORGOT PASSWORD
# --------------------------------------------------

@router.post(
    "/forgot-password",
    status_code=status.HTTP_200_OK,
    summary="Request password reset",
)
def forgot_password(
    payload: ForgotPasswordRequest,
    db: Session = Depends(get_db),
):
    user = get_user_by_email(db, email=payload.email)
    response_data = {
        "message": "If that address exists, a password reset link has been sent."
    }

    if user and user.is_active:
        token = create_reset_token(user.email)
        reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token}"
        subject = "ThreatLens — Password Reset Request"
        html = (
            f"<p>Hello {user.full_name},</p>"
            "<p>You requested a password reset for your ThreatLens account. "
            f"Click the link below to set a new password:</p>"
            f"<p><a href='{reset_link}'>{reset_link}</a></p>"
            "<p>This link expires in 15 minutes. If you did not request this, you can ignore this email.</p>"
        )

        has_smtp = bool(alert_settings.smtp_username and alert_settings.smtp_password)
        if has_smtp:
            send_email(user.email, subject, html)
        else:
            logger.warning("Password reset link for %s: %s", user.email, reset_link)

        is_dev = settings.ENVIRONMENT.lower() in ("development", "dev", "test", "testing")
        if is_dev:
            response_data["dev_reset_link"] = reset_link

    return response_data


# --------------------------------------------------
# RESET PASSWORD
# --------------------------------------------------

@router.post(
    "/reset-password",
    status_code=status.HTTP_200_OK,
    summary="Reset password with token",
)
def reset_password(
    payload: ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    email = decode_reset_token(payload.token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )

    user = get_user_by_email(db, email=email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found"
        )

    user.password = hash_password(payload.new_password)
    db.commit()

    return {"message": "Password reset successfully"}


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@router.post(
    "/login",
    response_model=Token
)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    # OAuth2 uses "username", but our application
    # uses email as the username.
    user = UserLogin(
        email=form_data.username,
        password=form_data.password
    )

    token = login_user(db, user)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    return token


# --------------------------------------------------
# GET PROFILE
# --------------------------------------------------

@router.get(
    "/profile",
    response_model=UserResponse
)
def get_profile(
    current_user: User = Depends(get_current_user)
):
    return get_user_profile(current_user)


# --------------------------------------------------
# UPDATE PROFILE
# --------------------------------------------------

@router.put(
    "/profile",
    response_model=UserResponse
)
def update_profile(
    profile_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return update_user_profile(
        db,
        current_user,
        profile_data
    )


# --------------------------------------------------
# DELETE PROFILE
# --------------------------------------------------

@router.delete("/profile")
def delete_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    delete_user_profile(
        db,
        current_user
    )

    return {
        "message": "User account successfully deleted"
    }


# --------------------------------------------------
# ADMIN DASHBOARD - RBAC EXAMPLE
# --------------------------------------------------

@router.get(
    "/admin/dashboard",
    dependencies=[
        Depends(RoleChecker([UserRole.ADMINISTRATOR]))
    ]
)
def admin_dashboard(
    current_user: User = Depends(get_current_user)
):
    return {
        "message": (
            f"Welcome Admin {current_user.full_name} "
            "to ThreatLens Admin Dashboard"
        ),
        "system_status": (
            "All malware detection engines operational"
        )
    }