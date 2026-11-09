"""Case-scoped, short-lived access grants for safe Mac diagnostics.

Does not include MDM bypass functionality, remote code execution, or Apple-server blocking.
"""
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from app.models import DeviceAccessGrant, DeviceRecord, Order, FeasibilityReview
from app.security import secret

STAGES = {"CHECK", "KIT_DOWNLOAD", "SUPPORT"}

def serial_fingerprint(serial: str) -> str:
    return hmac.new(secret().encode(), serial.upper().encode(), hashlib.sha256).hexdigest()

def normalize_serial(raw: str) -> str | None:
    value = (raw or "").strip().upper()
    return value if re.fullmatch(r"[A-Z0-9]{6,24}", value) else None

def is_paid(db, item) -> bool:
    from app.models import RecoveryCase
    # A confirmed order belongs to the canonical Mac identity, not merely one case.
    return db.scalar(select(Order.id).join(RecoveryCase, RecoveryCase.id == Order.case_id).where(
        RecoveryCase.serial_hash == item.serial_hash,
        RecoveryCase.user_id == item.user_id,
        Order.user_id == item.user_id,
        Order.status == "PAID",
    ).limit(1)) is not None

def feasibility_state(db, item) -> str:
    reviewed = db.get(FeasibilityReview, item.id)
    return reviewed.state if reviewed else "PENDING"

def can_use_support(db, item) -> bool:
    return bool(item.ownership_verified and item.status != "CLOSED" and
                feasibility_state(db, item) == "ELIGIBLE" and is_paid(db, item))

def make_grant(db, item, user_id: str, stage: str) -> str:
    if stage not in STAGES:
        raise ValueError("Invalid stage")
    token = secrets.token_urlsafe(32)
    db.add(DeviceAccessGrant(
        case_id=item.id, user_id=user_id,
        stage=stage, token_hash=hashlib.sha256(token.encode()).hexdigest(),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
    ))
    return token

def redeem_grant(db, *, case_id: str, code: str, stage: str, serial: str):
    """Consume once; serial must match the case, even if the payment is already PAID.

    Caller must treat an invalid token and an unknown case uniformly.
    """
    if stage not in STAGES or not re.fullmatch(r"[A-Za-z0-9_-]{40,100}", code or ""):
        return None
    token_hash = hashlib.sha256(code.encode()).hexdigest()
    grant = db.scalar(select(DeviceAccessGrant).where(
        DeviceAccessGrant.token_hash == token_hash,
        DeviceAccessGrant.case_id == case_id,
        DeviceAccessGrant.stage == stage,
    ))
    now = datetime.now(timezone.utc)
    if not grant or grant.used_at or grant.expires_at.replace(tzinfo=timezone.utc) <= now:
        return None
    from app.models import RecoveryCase
    item = db.get(RecoveryCase, case_id)
    if not item or item.user_id != grant.user_id or item.serial_hash != serial_fingerprint(serial):
        grant.used_at = now
        db.commit()
        return None
    grant.used_at = now
    device = db.scalar(select(DeviceRecord).where(DeviceRecord.serial_hash == item.serial_hash))
    if device and device.user_id == item.user_id:
        device.last_checked_at = now
    db.commit()
    return item

def eligibility(db, item) -> tuple[str, str]:
    if item.status == "CLOSED":
        return "CASE_CLOSED", "This support case is closed. Contact support before continuing."
    if not item.ownership_verified:
        return "REVIEW_REQUIRED", "Ownership review is pending. You can check again after review."
    status = feasibility_state(db, item)
    if status == "INELIGIBLE":
        return "NOT_ELIGIBLE", "A specialist has marked this support procedure unavailable for this case."
    if status != "ELIGIBLE":
        return "FEASIBILITY_REVIEW", "Technical eligibility is awaiting specialist review."
    if is_paid(db, item):
        return "PAID", "Payment confirmed. Sign in to download the authorized support kit."
    return "PAYMENT_REQUIRED", "Eligible for a paid specialist assessment. Sign in to choose a plan."
