import os
import re
import tempfile
from pathlib import Path
import hashlib
import hmac
from urllib.parse import urlparse

# Isolated DB; tests must not touch real account data.
DB_FILE = Path(tempfile.gettempdir()) / "aht-revive-pytest.db"
os.environ["DATABASE_URL"] = f"sqlite:///{DB_FILE}"
os.environ["APP_ENV"] = "testing"
os.environ["APP_SECRET"] = "a-long-test-secret-that-is-never-used-in-production"
os.environ.pop("STRIPE_SECRET_KEY", None)

from fastapi.testclient import TestClient
import pytest
from app.main import app
from app.database import Base, engine, SessionLocal
from app.models import User, RecoveryCase
from app.commerce import validate_webhook
from sqlalchemy import select

@pytest.fixture
def client():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        yield c

def csrf(c, path="/register"):
    page = c.get(path)
    assert page.status_code == 200
    return re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)

def signup(c, email="hello@example.com"):
    token = csrf(c)
    r = c.post("/register", data={"csrf_token": token, "name": "Taylor Example", "email": email,
                                    "password": "StrongPassword123!"}, follow_redirects=False)
    assert r.status_code == 303
    return token

def open_case(c, token):
    r = c.post("/cases", data={
        "csrf_token": token, "device_model": "MacBook Pro 16-inch", "processor": "Apple M4",
        "macos": "Sequoia", "serial": "C02ABCDEF123", "issue": "RECOVERY",
        "description": "This Mac is stuck at recovery when trying to reinstall macOS.",
        "ownership_reference": "Receipt-123456", "attest": "yes"
    }, follow_redirects=False)
    assert r.status_code == 303
    return urlparse(r.headers["location"]).path.rsplit("/", 1)[1]

def test_landing_and_static(client):
    assert "Know your Mac" in client.get("/").text
    assert "AHT Revive" in client.get("/").text
    assert "Avenquill" not in client.get("/").text
    assert client.get("/healthz").json() == {"ok": True}
    assert "device identification & eligibility" in client.get("/services").text.lower()
    assert client.get("/static/site.css").status_code == 200
    assert "No guarantee of MDM removal" in client.get("/").text

def test_register_login_logout_and_csrf(client):
    assert client.post("/register", data={"email": "x@x.com"}).status_code == 403
    token = signup(client)
    assert "Welcome back" in client.get("/dashboard").text
    assert client.get("/admin").status_code == 403
    assert client.post("/logout", data={"csrf_token": token}, follow_redirects=False).status_code == 303
    assert client.get("/dashboard", follow_redirects=False).status_code == 303
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf_token": token, "email": "hello@example.com",
                                    "password": "StrongPassword123!"}, follow_redirects=False)
    assert r.status_code == 303
    assert "Your devices & cases" in client.get("/dashboard").text

def test_case_creation_and_access(client):
    token = signup(client)
    case_id = open_case(client, token)
    r = client.get(f"/cases/{case_id}")
    assert r.status_code == 200
    assert "MacBook Pro 16-inch" in r.text
    assert "F123" in r.text
    assert "C02ABCDEF123" not in r.text
    assert client.post(f"/cases/{case_id}/checkout", data={"csrf_token": token, "plan": "assessment"},
                       follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        item = db.get(RecoveryCase, case_id)
        assert item.serial_hash == hmac.new(os.environ["APP_SECRET"].encode(), b"C02ABCDEF123", hashlib.sha256).hexdigest()
        assert not item.ownership_verified
    assert client.post(f"/cases/{case_id}/messages", data={"csrf_token": token,"body":"Additional notes here."},
                       follow_redirects=False).status_code == 303
    assert "Additional notes here" in client.get(f"/cases/{case_id}").text


def test_cross_account_isolation_and_admin_review(client):
    t = signup(client)
    case_id = open_case(client, t)
    client.post("/logout", data={"csrf_token": t})
    t2 = signup(client, "another@example.com")
    assert client.get(f"/cases/{case_id}").status_code == 404
    assert client.post(f"/cases/{case_id}/messages", data={"csrf_token": t2,"body":"Intrude"}).status_code == 404
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == "another@example.com"))
        user.role = "ADMIN"
        db.commit()
    assert client.get("/admin").status_code == 200
    r = client.post(f"/admin/cases/{case_id}/update", data={"csrf_token": t2,
        "status":"VERIFIED", "ownership_verified":"yes"}, follow_redirects=False)
    assert r.status_code == 303
    with SessionLocal() as db:
        item = db.get(RecoveryCase, case_id)
        assert item.ownership_verified and item.status == "VERIFIED"
    r = client.post(f"/admin/cases/{case_id}/update", data={"csrf_token": t2,"status":"IN_PROGRESS"},follow_redirects=False)
    assert "Verify" in r.headers["location"]


def test_stripe_webhook_bad_signature(client):
    assert client.post("/webhooks/stripe", content=b'{}', headers={"stripe-signature":"t=123,v1=xx"}).status_code == 400


def test_script_has_no_bypass_payload(client):
    # This project intentionally offers human-reviewed recovery support, not an automated injector.
    for path in ["/", "/services", "/how-it-works"]:
        text = client.get(path).text
        assert "curl | sh" not in text


def test_signed_stripe_event_is_idempotent_and_checks_amount(client, monkeypatch):
    import json
    import time
    from app.models import Order, StripeEvent
    token = signup(client)
    case_id = open_case(client, token)
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == "hello@example.com"))
        order = Order(user_id=user.id, case_id=case_id, plan="assessment", amount_cents=3900,
                      stripe_session_id="cs_test_checkout123")
        db.add(order)
        db.commit()
        order_id = order.id
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_very_secret")

    def send(event_id, amount):
        payload = json.dumps({
            "id": event_id, "type": "checkout.session.completed",
            "data": {"object": {
                "id": "cs_test_checkout123", "metadata": {"order_id": order_id},
                "client_reference_id": order_id,
                "currency": "usd", "amount_total": amount, "payment_status": "paid"
            }}
        }).encode()
        now = str(int(time.time()))
        signature = hmac.new(b"whsec_test_very_secret",now.encode()+b"."+payload,hashlib.sha256).hexdigest()
        return client.post("/webhooks/stripe", content=payload,
                           headers={"stripe-signature":f"t={now},v1={signature}"})

    assert send("evt_wrong_amount", 5).status_code == 200
    with SessionLocal() as db:
        assert db.get(Order,order_id).status == "PENDING"
    assert send("evt_correct_amount", 3900).status_code == 200
    assert send("evt_correct_amount", 3900).json().get("duplicate") is True
    with SessionLocal() as db:
        assert db.get(Order,order_id).status == "PAID"
        assert db.get(StripeEvent,"evt_correct_amount") is not None


def test_password_reset_changes_password_and_revokes_existing_sessions(client):
    from datetime import datetime, timedelta, timezone
    from app.models import PasswordReset
    token = signup(client)
    assert client.get("/dashboard").status_code == 200
    raw = "F" * 40
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email=="hello@example.com"))
        db.add(PasswordReset(user_id=user.id, token_hash=hashlib.sha256(raw.encode()).hexdigest(),
                             expires_at=datetime.now(timezone.utc)+timedelta(minutes=30)))
        db.commit()
    t = csrf(client, f"/reset-password/{raw}")
    r = client.post(f"/reset-password/{raw}", data={"csrf_token":t, "password":"NewSecurePassword456!"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/dashboard", follow_redirects=False).status_code == 303
    assert client.get(f"/reset-password/{raw}").status_code == 200
    r = client.post(f"/reset-password/{raw}",data={"csrf_token":t,"password":"AnotherGoodPassword!"},
                    follow_redirects=False)
    assert "expired" in r.headers["location"]
    signin_csrf = csrf(client, "/login")
    assert client.post("/login",data={"csrf_token":signin_csrf,"email":"hello@example.com",
                  "password":"NewSecurePassword456!"},follow_redirects=False).status_code==303
    assert client.get("/dashboard").status_code == 200


def test_password_reset_request_does_not_expose_account_existence(client):
    token = csrf(client, "/forgot-password")
    r = client.post("/forgot-password", data={"csrf_token":token,"email":"unknown@example.com"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/forgot-password?sent=1"


def issue_code(client, token, case_id, stage):
    r = client.post(f"/cases/{case_id}/access-code", data={"csrf_token": token, "stage": stage})
    assert r.status_code == 200
    strings = re.findall(r'<div class="copy-code">([^<]+)</div>', r.text)
    assert len(strings) == 2
    assert strings[0] == case_id
    return strings[1]


def test_free_checker_and_protected_support_download(client):
    token = signup(client)
    case_id = open_case(client, token)
    assert client.get("/downloads/mac-check.sh").status_code == 200
    assert "read-only" in client.get("/downloads/mac-check.sh").text
    assert client.get("/cases/%s/download-support" % case_id).status_code == 403
    bad = client.post("/api/v1/device/check", data={"serial": "C02ABCDEF123", "case_id":case_id,"access_code":"wrong"})
    assert bad.status_code == 401
    check_code = issue_code(client, token, case_id, "CHECK")
    r = client.post("/api/v1/device/check", data={"serial": "C02ABCDEF123", "case_id":case_id,
                                                "access_code":check_code})
    assert r.status_code == 200
    assert "STATE=REVIEW_REQUIRED" in r.text
    # One-time means replay cannot be used to enumerate payment state.
    assert client.post("/api/v1/device/check", data={"serial":"C02ABCDEF123", "case_id":case_id,
                                                     "access_code":check_code}).status_code == 401
    denied = client.post(f"/cases/{case_id}/access-code", data={"csrf_token":token,"stage":"SUPPORT"})
    assert denied.status_code == 403


def test_serial_matches_hardware_and_no_public_enumeration(client):
    token = signup(client)
    case_id = open_case(client, token)
    check_code = issue_code(client, token, case_id, "CHECK")
    mismatch = client.post("/api/v1/device/check", data={"serial":"C02ZZZZZZ999", "case_id":case_id,
                                                      "access_code":check_code})
    assert mismatch.status_code == 401
    assert client.post("/api/v1/device/check", data={"serial":"C02ABCDEF123", "case_id":case_id,
                                                     "access_code":check_code}).status_code == 401
    from app.models import DeviceRecord
    with SessionLocal() as db:
        devices = db.scalars(select(DeviceRecord)).all()
        assert len(devices) == 1
        assert devices[0].serial_suffix == "F123"
        assert devices[0].serial_hash != "C02ABCDEF123"
    # Another account cannot silently attach the same serial to a new record.
    client.post("/logout", data={"csrf_token":token})
    token = signup(client, "another@example.com")
    r = client.post("/cases", data={"csrf_token":token,"device_model":"MacBook Pro 16-inch",
            "processor":"Apple M4", "macos":"Tahoe", "serial":"C02ABCDEF123",
            "issue":"RECOVERY", "description":"A different owner is submitting a review request for the same device.",
            "ownership_reference":"Receipt-123456", "attest":"yes"}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/cases/new?")


def test_paid_device_entitlement_grants_separate_script(client):
    from app.models import Order, DeviceRecord, FeasibilityReview
    token = signup(client)
    case_id = open_case(client, token)
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == "hello@example.com"))
        case = db.get(RecoveryCase, case_id)
        case.ownership_verified = True
        case.status = "VERIFIED"
        review = db.get(FeasibilityReview, case_id)
        review.state = "ELIGIBLE"
        db.add(Order(user_id=user.id, case_id=case_id, plan="assessment", amount_cents=3900, status="PENDING"))
        db.commit()
    code = issue_code(client, token, case_id, "CHECK")
    r = client.post("/api/v1/device/check", data={"serial":"C02ABCDEF123", "case_id":case_id,"access_code":code})
    assert "STATE=PAYMENT_REQUIRED" in r.text
    assert client.get(f"/cases/{case_id}/download-support").status_code == 403
    with SessionLocal() as db:
        order = db.scalar(select(Order).where(Order.case_id == case_id))
        order.status = "PAID"  # simulated after signed webhook, not a public action
        db.commit()
    code = issue_code(client, token, case_id, "CHECK")
    r = client.post("/api/v1/device/check", data={"serial":"C02ABCDEF123", "case_id":case_id,"access_code":code})
    assert "STATE=PAID" in r.text
    r = client.get(f"/cases/{case_id}/download-support")
    assert r.status_code == 200
    assert "read-only" in r.text
    stage_code = issue_code(client, token, case_id, "SUPPORT")
    r = client.post("/api/v1/device/support-authorization", data={"serial":"C02ABCDEF123", "case_id":case_id,"access_code":stage_code})
    assert r.status_code == 200
    assert r.text.startswith("STATE=AUTHORIZED")
    assert client.post("/api/v1/device/support-authorization", data={"serial":"C02ABCDEF123", "case_id":case_id,"access_code":stage_code}).status_code == 401
    # Revoking ownership must immediately revoke future support authorization.
    with SessionLocal() as db:
        case = db.get(RecoveryCase, case_id)
        case.ownership_verified = False
        db.commit()
    assert client.get(f"/cases/{case_id}/download-support").status_code == 403


def test_code_expiration_and_stage_isolation(client):
    from app.models import DeviceAccessGrant
    from datetime import datetime, timedelta, timezone
    token = signup(client)
    case_id = open_case(client, token)
    check_code = issue_code(client, token, case_id, "CHECK")
    assert client.post("/api/v1/device/support-authorization", data={"serial":"C02ABCDEF123", "case_id":case_id,
                                  "access_code":check_code}).status_code == 401
    with SessionLocal() as db:
        grant = db.scalar(select(DeviceAccessGrant))
        grant.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    assert client.post("/api/v1/device/check", data={"serial":"C02ABCDEF123", "case_id":case_id,
                                  "access_code":check_code}).status_code == 401


def test_feasibility_review_precedes_payment_and_support(client):
    from app.models import FeasibilityReview, Order
    token = signup(client)
    case_id = open_case(client, token)
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == "hello@example.com"))
        case = db.get(RecoveryCase, case_id)
        case.ownership_verified = True
        db.add(Order(user_id=user.id, case_id=case_id, plan="assessment", amount_cents=3900, status="PAID"))
        db.commit()
    code = issue_code(client, token, case_id, "CHECK")
    r = client.post("/api/v1/device/check", data={"serial":"C02ABCDEF123", "case_id":case_id,"access_code":code})
    assert "STATE=FEASIBILITY_REVIEW" in r.text
    assert client.get(f"/cases/{case_id}/download-support").status_code == 403
    with SessionLocal() as db:
        db.get(FeasibilityReview, case_id).state = "INELIGIBLE"
        db.commit()
    code = issue_code(client, token, case_id, "CHECK")
    r = client.post("/api/v1/device/check", data={"serial":"C02ABCDEF123", "case_id":case_id,"access_code":code})
    assert "STATE=NOT_ELIGIBLE" in r.text
    assert client.get(f"/cases/{case_id}/download-support").status_code == 403


def test_device_scoped_payment_applies_to_same_mac_other_case(client):
    from app.models import Order, FeasibilityReview, DeviceRecord
    token = signup(client)
    first = open_case(client, token)
    second = open_case(client, token)
    assert first != second
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == "hello@example.com"))
        for case_id in (first, second):
            item = db.get(RecoveryCase, case_id)
            item.ownership_verified = True
            db.get(FeasibilityReview, case_id).state = "ELIGIBLE"
        db.add(Order(user_id=user.id, case_id=first, plan="assessment", amount_cents=3900, status="PAID"))
        db.commit()
        assert len(db.scalars(select(DeviceRecord)).all()) == 1
    code = issue_code(client, token, second, "CHECK")
    assert "STATE=PAID" in client.post("/api/v1/device/check", data={"serial":"C02ABCDEF123", "case_id":second,
                                                   "access_code":code}).text
    assert client.get(f"/cases/{second}/download-support").status_code == 200


def test_free_script_origin_is_embedded_and_not_a_paid_kit(client, monkeypatch):
    monkeypatch.setenv("APP_URL", "https://aht.example.test")
    r = client.get("/downloads/mac-check.sh")
    assert r.status_code == 200
    assert "https://aht.example.test" in r.text
    assert "example.invalid" not in r.text
    assert "csrutil status" not in r.text  # advanced diagnostic isn't accidentally bundled
    assert r.headers["cache-control"] == "private, no-store"


def test_paid_checker_handoff_download_is_one_time_and_hashed(client):
    from app.models import FeasibilityReview, Order
    token = signup(client)
    case_id = open_case(client, token)
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == "hello@example.com"))
        item = db.get(RecoveryCase, case_id)
        item.ownership_verified = True
        db.get(FeasibilityReview, case_id).state = "ELIGIBLE"
        db.add(Order(user_id=user.id, case_id=case_id, plan="assessment", amount_cents=3900, status="PAID"))
        db.commit()
    code = issue_code(client, token, case_id, "CHECK")
    result = client.post("/api/v1/device/check", data={"serial":"C02ABCDEF123", "case_id":case_id,"access_code":code})
    assert result.status_code == 200
    assert result.headers["cache-control"] == "no-store"
    assert "STATE=PAID" in result.text
    handoff_token = re.search(r"^KIT_CODE=(.+)$", result.text, re.M).group(1)
    digest = re.search(r"^KIT_SHA256=([0-9a-f]{64})$", result.text, re.M).group(1)
    payload = {"serial":"C02ABCDEF123", "case_id":case_id,"access_code":handoff_token}
    kit = client.post("/api/v1/device/kit", data=payload)
    assert kit.status_code == 200
    assert hashlib.sha256(kit.content).hexdigest() == digest
    assert "read-only" in kit.text
    assert client.post("/api/v1/device/kit", data=payload).status_code == 403
    assert client.post("/api/v1/device/kit", data={**payload,"serial":"C02ZZZZZZ999"}).status_code == 403
