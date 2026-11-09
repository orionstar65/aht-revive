"""Explicit one-time admin promotion: python -m scripts.promote_admin email@example.com"""
import sys
from sqlalchemy import select
from app.database import SessionLocal, init_db
from app.models import User

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m scripts.promote_admin email@example.com")
    init_db()
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == sys.argv[1].strip().lower()))
        if not user:
            raise SystemExit("No such registered user")
        user.role = "ADMIN"
        db.commit()
    print("Administrator role assigned")
