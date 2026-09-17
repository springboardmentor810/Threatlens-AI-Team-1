"""
Create the four demo accounts the login page's account picker offers.

One per platform role, so RBAC can be exercised end to end: an analyst gets 403
where an administrator gets 204, a researcher sees only alerts addressed to
them, and so on.

    python scripts/seed_demo_accounts.py

Idempotent: existing accounts have their password reset to the demo value
rather than being duplicated, so the picker always works after a run.

DEMO CREDENTIALS ONLY. Every account here shares one well-known password. Do
not run this against anything reachable from a network you do not control.
"""

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

# The backend resolves a relative sqlite path against the working directory,
# and it is normally started from backend/. Anchor it so this script writes to
# the same file however it is invoked.
if not os.getenv("DATABASE_URL"):
    os.environ["DATABASE_URL"] = f"sqlite:///{(REPO_ROOT / 'backend' / 'threatlens.db').as_posix()}"

from app.auth.security import hash_password  # noqa: E402
from app.database.database import Base, SessionLocal, engine  # noqa: E402
from app.models.user import User  # noqa: E402

# Imported so their tables are part of the metadata create_all below.
from app.alerts import models as _alert_models  # noqa: E402,F401
from app.modules.threat_monitoring import models as _threat_models  # noqa: E402,F401

DEMO_PASSWORD = "ThreatLens123!"

# Emails match database/sample_data/sample_users.sql so the two seeds agree.
DEMO_ACCOUNTS = [
    ("ThreatLens Administrator", "admin@threatlens.ai", "administrator"),
    ("Senior Security Analyst", "analyst.senior@threatlens.ai", "security_analyst"),
    ("SOC Duty Officer", "soc.duty@threatlens.ai", "soc_team_member"),
    ("Malware Researcher", "researcher@threatlens.ai", "researcher"),
]


def main() -> int:
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    created, reset = 0, 0
    try:
        for full_name, email, role in DEMO_ACCOUNTS:
            user = db.query(User).filter(User.email == email).first()
            if user:
                # Reset rather than skip: a stale password would make the
                # login page's picker offer credentials that do not work.
                user.password = hash_password(DEMO_PASSWORD)
                user.role = role
                user.is_active = True
                reset += 1
                action = "reset"
            else:
                db.add(
                    User(
                        full_name=full_name,
                        email=email,
                        password=hash_password(DEMO_PASSWORD),
                        role=role,
                        is_active=True,
                    )
                )
                created += 1
                action = "created"
            print(f"  {action:8} {email:32} {role}")
        db.commit()
    finally:
        db.close()

    print(f"\n{created} created, {reset} reset.")
    print(f"Password for all of them: {DEMO_PASSWORD}")
    print(f"Database: {os.environ['DATABASE_URL']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
