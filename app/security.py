import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from sqlalchemy import select
from app.models import Session, User

hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
SESSION_DAYS = 7

def secret():
    value = os.getenv("APP_SECRET", "")
    if len(value) < 32:
        if os.getenv("APP_ENV") == "production":
            raise RuntimeError("APP_SECRET must be at least 32 characters in production")
        return "dev-only-secret-never-use-in-production-please-change"
    return value

def password_hash(password: str) -> str:
    return hasher.hash(password)

def verify_password(hash_: str, password: str) -> bool:
    try:
        return bool(hasher.verify(hash_, password))
    except (VerifyMismatchError, VerificationError):
        return False

def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

def create_session(db, user: User) -> str:
    token = secrets.token_urlsafe(32)
    db.add(Session(user_id=user.id, token_hash=digest(token), expires_at=datetime.now(timezone.utc)+timedelta(days=SESSION_DAYS)))
    db.commit()
    return token

def find_user(db, raw_token: str | None):
    if not raw_token:
        return None
    session = db.scalar(select(Session).where(Session.token_hash == digest(raw_token)))
    if not session:
        return None
    expiry = session.expires_at
    if expiry.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return None
    return db.get(User, session.user_id)

def end_session(db, token: str | None):
    if token:
        session = db.scalar(select(Session).where(Session.token_hash == digest(token)))
        if session:
            db.delete(session)
            db.commit()

def sign_nonce(nonce: str):
    mac = hmac.new(secret().encode(), nonce.encode(), hashlib.sha256).hexdigest()
    return f"{nonce}.{mac}"

def parse_nonce(cookie: str | None):
    if not cookie or "." not in cookie:
        return None
    nonce, signature = cookie.rsplit(".", 1)
    if len(nonce) < 24 or len(nonce) > 128:
        return None
    expected = sign_nonce(nonce).rsplit(".", 1)[1]
    return nonce if hmac.compare_digest(signature, expected) else None

def csrf_valid(request, form):
    nonce = parse_nonce(request.cookies.get("csrf"))
    return bool(nonce and hmac.compare_digest(nonce, str(form.get("csrf_token", ""))))
