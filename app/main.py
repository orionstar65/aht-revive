from __future__ import annotations
import os
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from pathlib import Path
from urllib.parse import quote
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from app.database import SessionLocal, init_db
from app.models import User, RecoveryCase, CaseMessage, Order, StripeEvent, LoginAttempt, AuditEvent, PasswordReset, ResetRequest, DeviceRecord, DeviceAccessGrant, FeasibilityReview
from app.security import (COOKIE_SECURE, csrf_valid, parse_nonce, sign_nonce, password_hash, secret,
                          verify_password, create_session, find_user, end_session)
from app.commerce import PLANS, start_checkout, validate_webhook
from app.mail import send_mail
from app.device_access import serial_fingerprint, normalize_serial, make_grant, redeem_grant, eligibility, is_paid, can_use_support, feasibility_state

BASE_DIR = Path(__file__).parent
ISSUES = {
    "ENROLLMENT": "Remote Management / enrollment guidance",
    "ACTIVATION": "Activation or ownership transfer",
    "RECOVERY": "macOS recovery / reinstall",
    "SECURITY": "Account and device security",
    "OTHER": "Other technical issue",
}
STATUSES = {"REVIEW", "VERIFIED", "IN_PROGRESS", "WAITING", "RESOLVED", "CLOSED"}

@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.getenv("APP_ENV") == "production" and (
        len(os.getenv("APP_SECRET", "")) < 32 or not COOKIE_SECURE
    ):
        raise RuntimeError("Production requires APP_SECRET (32+ chars) and COOKIE_SECURE=true")
    init_db()
    yield

app = FastAPI(title="AHT Revive", version="1.1.0", lifespan=lifespan,
              docs_url=None if os.getenv("APP_ENV") == "production" else "/api/docs")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.globals["ISSUES"] = ISSUES
templates.env.globals["PLANS"] = PLANS

@app.middleware("http")
async def headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if os.getenv("APP_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; form-action 'self' https://checkout.stripe.com; "
        "frame-ancestors 'none'; base-uri 'self'"
    )
    return response

def get_user(request: Request, db):
    return find_user(db, request.cookies.get("session"))

def require_user(request: Request, db):
    user = get_user(request, db)
    if not user:
        raise HTTPException(401, "Sign in required")
    return user

def require_admin(request: Request, db):
    user = require_user(request, db)
    if user.role != "ADMIN":
        raise HTTPException(403, "Administrator access required")
    return user

def get_case(db, case_id: str, user: User):
    item = db.scalar(select(RecoveryCase).options(selectinload(RecoveryCase.messages).selectinload(CaseMessage.author),
                                                      selectinload(RecoveryCase.orders)).where(RecoveryCase.id == case_id))
    if not item:
        raise HTTPException(404, "Case not found")
    if user.role != "ADMIN" and item.user_id != user.id:
        raise HTTPException(404, "Case not found")
    return item

def render(request, file, *, status=200, **kwargs):
    with SessionLocal() as db:
        user = get_user(request, db)
    nonce = parse_nonce(request.cookies.get("csrf"))
    new = nonce is None
    nonce = nonce or secrets.token_urlsafe(32)
    context = {"request": request, "user": user, "csrf_token": nonce,
               "brand": "AHT Revive", "year": datetime.now(timezone.utc).year,
               **kwargs}
    response = templates.TemplateResponse(request, file, context=context, status_code=status)
    if new:
        response.set_cookie("csrf", sign_nonce(nonce), max_age=604800, httponly=True,
                            secure=COOKIE_SECURE, samesite="lax", path="/")
    response.headers["Cache-Control"] = "private, no-store"
    return response

def check_csrf(request, form):
    if not csrf_valid(request, form):
        raise HTTPException(403, "Invalid form token. Reload the page and retry.")

def go(to: str, *, error: str | None = None):
    if error:
        to += ("&" if "?" in to else "?") + "error=" + quote(error[:180])
    return RedirectResponse(to, status_code=303)

def audit(db, actor_id, action, target_id):
    db.add(AuditEvent(actor_id=actor_id, action=action, target_id=target_id))

@app.exception_handler(HTTPException)
async def html_exception(request, exc):
    if request.url.path.startswith("/api/") or request.url.path.startswith("/webhooks/"):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    return render(request, "error.html", status=exc.status_code, code=exc.status_code, message=exc.detail)

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return render(request, "home.html", active="home")

@app.get("/services", response_class=HTMLResponse)
def services(request: Request):
    return render(request, "services.html", active="services")

@app.get("/how-it-works", response_class=HTMLResponse)
def how(request: Request):
    return render(request, "how.html", active="how")

@app.get("/faq", response_class=HTMLResponse)
def faq(request: Request):
    return render(request, "faq.html", active="faq")

@app.get("/privacy", response_class=HTMLResponse)
def privacy(request: Request):
    return render(request, "legal.html", policy="privacy", heading="Privacy policy", active="privacy")

@app.get("/terms", response_class=HTMLResponse)
def terms(request: Request):
    return render(request, "legal.html", policy="terms", heading="Terms of service", active="terms")

@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    with SessionLocal() as db:
        if get_user(request, db): return go("/dashboard")
    return render(request, "auth.html", mode="register", active="register")

@app.post("/register")
async def register(request: Request):
    form = await request.form()
    check_csrf(request, form)
    name = str(form.get("name", "")).strip()
    email = str(form.get("email", "")).strip().lower()
    password = str(form.get("password", ""))
    if len(name) < 2 or len(name) > 120 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
        return go("/register", error="Enter a valid name and email address")
    if len(password) < 12 or len(password) > 256:
        return go("/register", error="Use a password of 12–256 characters")
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.email == email)):
            return go("/register", error="This email is already registered")
        user = User(name=name, email=email, password_hash=password_hash(password), role="CUSTOMER")
        db.add(user)
        db.commit()
        token = create_session(db, user)
    response = go("/dashboard?welcome=1")
    response.set_cookie("session", token, max_age=7*86400, httponly=True,
                        secure=COOKIE_SECURE, samesite="lax", path="/")
    return response

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    with SessionLocal() as db:
        if get_user(request, db): return go("/dashboard")
    return render(request, "auth.html", mode="login", active="login")

@app.post("/login")
async def login(request: Request):
    form = await request.form()
    check_csrf(request, form)
    email = str(form.get("email", "")).strip().lower()[:254]
    password = str(form.get("password", ""))
    ip = request.client.host if request.client else "unknown"
    with SessionLocal() as db:
        since = datetime.now(timezone.utc) - timedelta(minutes=15)
        failures = db.scalar(select(func.count()).select_from(LoginAttempt).where(
            LoginAttempt.email == email, LoginAttempt.created_at >= since)) or 0
        if failures >= 8:
            return go("/login", error="Too many attempts. Please try again in 15 minutes")
        user = db.scalar(select(User).where(User.email == email))
        if not user or not verify_password(user.password_hash, password):
            db.add(LoginAttempt(email=email, ip=ip))
            db.commit()
            return go("/login", error="Incorrect email or password")
        db.query(LoginAttempt).filter(LoginAttempt.email == email).delete()
        db.commit()
        token = create_session(db, user)
    response = go("/dashboard")
    response.set_cookie("session", token, max_age=7*86400, httponly=True,
                        secure=COOKIE_SECURE, samesite="lax", path="/")
    return response

@app.get("/forgot-password", response_class=HTMLResponse)
def forgot_form(request: Request):
    return render(request, "account_reset.html", mode="request")

@app.post("/forgot-password")
async def forgot_submit(request: Request, tasks: BackgroundTasks):
    form = await request.form()
    check_csrf(request, form)
    email = str(form.get("email", "")).strip().lower()[:254]
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return go("/forgot-password?sent=1")
    with SessionLocal() as db:
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        count = db.scalar(select(func.count()).select_from(ResetRequest).where(
            ResetRequest.email == email, ResetRequest.created_at >= since)) or 0
        if count < 3:
            db.add(ResetRequest(email=email))
            user = db.scalar(select(User).where(User.email == email))
            if user and os.getenv("SMTP_HOST") and os.getenv("SMTP_FROM"):
                token = secrets.token_urlsafe(32)
                record = PasswordReset(user_id=user.id, token_hash=hashlib.sha256(token.encode()).hexdigest(),
                    expires_at=datetime.now(timezone.utc)+timedelta(minutes=30))
                db.add(record)
                base = os.getenv("APP_URL", str(request.base_url).rstrip("/"))
                tasks.add_task(send_mail, user.email, "Reset your AHT Revive password",
                    f"A password reset was requested for your account.\n\nOpen this link within 30 minutes:\n{base}/reset-password/{token}\n\nIf you didn't request this, ignore this email.")
            db.commit()
    return go("/forgot-password?sent=1")

@app.get("/reset-password/{token}", response_class=HTMLResponse)
def reset_form(request: Request, token: str):
    if not re.fullmatch(r"[A-Za-z0-9_-]{30,100}", token):
        raise HTTPException(400, "Invalid reset link")
    return render(request, "account_reset.html", mode="reset", token=token)

@app.post("/reset-password/{token}")
async def reset_submit(request: Request, token: str):
    form = await request.form()
    check_csrf(request, form)
    password = str(form.get("password", ""))
    if len(password) < 12 or len(password) > 256:
        return go(f"/reset-password/{token}", error="Use a password of 12–256 characters")
    with SessionLocal() as db:
        record = db.scalar(select(PasswordReset).where(PasswordReset.token_hash == hashlib.sha256(token.encode()).hexdigest()))
        if not record or record.used_at or record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            return go("/forgot-password", error="This reset link is invalid or expired")
        user = db.get(User, record.user_id)
        user.password_hash = password_hash(password)
        record.used_at = datetime.now(timezone.utc)
        from app.models import Session as AccountSession
        db.query(AccountSession).filter(AccountSession.user_id == user.id).delete()
        audit(db, user.id, "password_reset", user.id)
        db.commit()
    response = go("/login?reset=1")
    response.delete_cookie("session", path="/")
    return response

@app.post("/logout")
async def logout(request: Request):
    form = await request.form()
    check_csrf(request, form)
    with SessionLocal() as db:
        end_session(db, request.cookies.get("session"))
    response = go("/")
    response.delete_cookie("session", path="/")
    return response

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    with SessionLocal() as db:
        user = get_user(request, db)
        if not user: return go("/login")
        cases = db.scalars(select(RecoveryCase).where(RecoveryCase.user_id == user.id).order_by(RecoveryCase.created_at.desc())).all()
        orders = db.scalars(select(Order).where(Order.user_id == user.id).order_by(Order.created_at.desc())).all()
        stats = {"open": len([c for c in cases if c.status not in {"RESOLVED", "CLOSED"}]),
                 "verified": len([c for c in cases if c.ownership_verified]),
                 "orders": len([o for o in orders if o.status == "PAID"])}
        return render(request, "dashboard.html", cases=cases, orders=orders, stats=stats, active="dashboard")

@app.get("/cases/new", response_class=HTMLResponse)
def new_case_form(request: Request):
    with SessionLocal() as db:
        if not get_user(request, db): return go("/login")
    return render(request, "new_case.html", active="dashboard")

@app.post("/cases")
async def create_case(request: Request, tasks: BackgroundTasks):
    form = await request.form()
    check_csrf(request, form)
    model = str(form.get("device_model", "")).strip()[:120]
    processor = str(form.get("processor", "")).strip()[:40]
    macos = str(form.get("macos", "")).strip()[:60]
    serial = str(form.get("serial", "")).strip().upper()
    issue = str(form.get("issue", ""))
    description = str(form.get("description", "")).strip()[:3000]
    ownership = str(form.get("ownership_reference", "")).strip()[:200]
    consent = form.get("attest") == "yes"
    if not (2 <= len(model) <= 120 and processor and macos and
            re.fullmatch(r"[A-Z0-9]{6,24}", serial) and issue in ISSUES and
            20 <= len(description) <= 3000 and 5 <= len(ownership) <= 200 and consent):
        return go("/cases/new", error="Please complete every field and confirm your authorization")
    with SessionLocal() as db:
        user = get_user(request, db)
        if not user: return go("/login")
        fingerprint = serial_fingerprint(serial)
        device = db.scalar(select(DeviceRecord).where(DeviceRecord.serial_hash == fingerprint))
        prior_case = db.scalar(select(RecoveryCase).where(RecoveryCase.serial_hash == fingerprint))
        # Never reveal the other account's identity or whether the serial is enrolled.
        if ((device and device.user_id != user.id) or
            (prior_case and prior_case.user_id != user.id)):
            return go("/cases/new", error="This device needs a manual account ownership review. Contact support.")
        if not device:
            device = DeviceRecord(user_id=user.id, serial_hash=fingerprint, serial_suffix=serial[-4:],
                                  device_model=model, processor=processor, macos=macos)
            db.add(device)
        item = RecoveryCase(user_id=user.id, device_model=model, processor=processor,
                            macos=macos, serial_suffix=serial[-4:], serial_hash=fingerprint,
                            issue=issue, description=description, ownership_reference=ownership)
        db.add(item)
        try:
            db.flush()
            db.add(FeasibilityReview(case_id=item.id, state="PENDING"))
        except IntegrityError:
            db.rollback()
            return go("/cases/new", error="Unable to register device; please contact support.")
        audit(db, user.id, "case_created", item.id)
        db.commit()
        support = os.getenv("SUPPORT_EMAIL")
        if support:
            tasks.add_task(send_mail, support, "New recovery case received", f"New case #{item.id[:8]}\nVisit {os.getenv('APP_URL', 'http://localhost:8000')}/admin")
        return go(f"/cases/{item.id}")

@app.get("/cases/{case_id}", response_class=HTMLResponse)
def case_details(request: Request, case_id: str):
    with SessionLocal() as db:
        user = get_user(request, db)
        if not user: return go("/login")
        item = get_case(db, case_id, user)
        return render(request, "case.html", item=item, paid=is_paid(db, item),
                      feasibility=feasibility_state(db, item), active="dashboard")

# Free public first-stage script; the browser account issues a short-lived case code.
def script_payload(filename: str) -> str:
    """Embed deployment origin at delivery time, without exposing server secrets."""
    origin = os.getenv("APP_URL", "http://localhost:8000").rstrip("/")
    if os.getenv("APP_ENV") == "production" and not origin.startswith("https://"):
        raise HTTPException(503, "A secure APP_URL must be configured")
    return (BASE_DIR.parent / "scripts" / filename).read_text().replace("https://example.invalid", origin)

def packaged_script(filename: str, download_name: str) -> Response:
    return Response(script_payload(filename), media_type="text/x-shellscript", headers={
        "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff",
        "Content-Disposition": f'attachment; filename="{download_name}"',
    })

@app.get("/downloads/mac-check.sh")
def mac_checker_download():
    return packaged_script("mac_check.sh", "aht-mac-check.sh")

@app.post("/cases/{case_id}/access-code", response_class=HTMLResponse)
async def issue_access_code(request: Request, case_id: str):
    form = await request.form()
    check_csrf(request, form)
    stage = str(form.get("stage", ""))
    if stage not in {"CHECK", "SUPPORT"}:
        raise HTTPException(400, "Invalid diagnostic stage")
    with SessionLocal() as db:
        user = require_user(request, db)
        item = get_case(db, case_id, user)
        if item.user_id != user.id:
            raise HTTPException(403, "Only the case owner can request a code")
        if stage == "SUPPORT" and not can_use_support(db, item):
            raise HTTPException(403, "Verified ownership and confirmed payment are required")
        recent = db.scalar(select(func.count(DeviceAccessGrant.id)).where(
            DeviceAccessGrant.user_id == user.id,
            DeviceAccessGrant.created_at >= datetime.now(timezone.utc) - timedelta(hours=1))) or 0
        if recent >= 10:
            raise HTTPException(429, "Too many codes requested. Please try again later")
        code = make_grant(db, item, user.id, stage)
        audit(db, user.id, "diagnostic_access_code_issued", item.id)
        db.commit()
        return render(request, "access_code.html", item=item, stage=stage, code=code,
                      app_url=os.getenv("APP_URL", str(request.base_url).rstrip("/")), active="dashboard")

@app.get("/cases/{case_id}/download-support")
def paid_support_download(request: Request, case_id: str):
    with SessionLocal() as db:
        user = require_user(request, db)
        item = get_case(db, case_id, user)
        if item.user_id != user.id or not can_use_support(db, item):
            raise HTTPException(403, "Verified ownership and confirmed payment are required")
        audit(db, user.id, "support_kit_downloaded", item.id)
        db.commit()
    return packaged_script("mac_support.sh", "aht-mac-support.sh")

@app.post("/api/v1/device/check")
async def device_check(request: Request):
    """One-use, customer-authorized case inquiry. Never a public serial payment lookup."""
    form = await request.form()
    case_id = str(form.get("case_id", ""))[:80]
    code = str(form.get("access_code", ""))[:200]
    serial = normalize_serial(str(form.get("serial", "")))
    if not serial:
        raise HTTPException(400, "Invalid serial number")
    with SessionLocal() as db:
        item = redeem_grant(db, case_id=case_id, code=code, stage="CHECK", serial=serial)
        if not item:
            raise HTTPException(401, "Invalid or expired case code, or device does not match")
        state, message = eligibility(db, item)
        # Paid+reviewed devices can fetch the second *read-only* script with a
        # short-lived one-time handoff. The client must verify digest and opt in.
        kit_code = make_grant(db, item, item.user_id, "KIT_DOWNLOAD") if state == "PAID" else ""
        audit(db, item.user_id, "device_check_" + state.lower(), item.id)
        db.commit()
    payload = f"STATE={state}\nDETAIL={message}\n"
    if kit_code:
        digest = hashlib.sha256(script_payload("mac_support.sh").encode()).hexdigest()
        payload += f"KIT_CODE={kit_code}\nKIT_SHA256={digest}\n"
    return PlainTextResponse(payload, headers={"Cache-Control": "no-store"})

@app.post("/api/v1/device/support-authorization")
async def support_authorization(request: Request):
    """Second independent check. Authorizes read-only diagnostics, not MDM bypass."""
    form = await request.form()
    case_id = str(form.get("case_id", ""))[:80]
    code = str(form.get("access_code", ""))[:200]
    serial = normalize_serial(str(form.get("serial", "")))
    if not serial:
        raise HTTPException(400, "Invalid serial number")
    with SessionLocal() as db:
        item = redeem_grant(db, case_id=case_id, code=code, stage="SUPPORT", serial=serial)
        if not item:
            raise HTTPException(401, "Invalid or expired case code, or device does not match")
        if not can_use_support(db, item):
            raise HTTPException(403, "Payment or ownership authorization is not confirmed")
        audit(db, item.user_id, "support_diagnostics_authorized", item.id)
        db.commit()
    return PlainTextResponse("STATE=AUTHORIZED\nDETAIL=Read-only diagnostics may proceed.\n", headers={"Cache-Control": "no-store"})

@app.post("/api/v1/device/kit")
async def authorized_kit_download(request: Request):
    """One-use handoff from the free checker to the separate read-only paid kit."""
    form = await request.form()
    case_id = str(form.get("case_id", ""))[:80]
    code = str(form.get("access_code", ""))[:200]
    serial = normalize_serial(str(form.get("serial", "")))
    if not serial:
        raise HTTPException(400, "Invalid serial number")
    with SessionLocal() as db:
        item = redeem_grant(db, case_id=case_id, code=code, stage="KIT_DOWNLOAD", serial=serial)
        if not item or not can_use_support(db, item):
            raise HTTPException(403, "Kit access not authorized or already used")
        audit(db, item.user_id, "read_only_kit_handoff", item.id)
        db.commit()
    return packaged_script("mac_support.sh", "aht-mac-support.sh")

@app.post("/cases/{case_id}/messages")
async def add_message(request: Request, case_id: str, tasks: BackgroundTasks):
    form = await request.form()
    check_csrf(request, form)
    body = str(form.get("body", "")).strip()
    if not (1 <= len(body) <= 3000): return go(f"/cases/{case_id}", error="Message must be 1–3000 characters")
    with SessionLocal() as db:
        user = require_user(request, db)
        item = get_case(db, case_id, user)
        if item.status == "CLOSED" and user.role != "ADMIN":
            return go(f"/cases/{case_id}", error="This case is closed")
        db.add(CaseMessage(case_id=case_id, author_id=user.id, body=body))
        item.updated_at = datetime.now(timezone.utc)
        destination = db.get(User, item.user_id).email if user.role == "ADMIN" else os.getenv("SUPPORT_EMAIL")
        if destination:
            tasks.add_task(send_mail, destination, "New case message — AHT Revive",
                f"There is a new message on case #{case_id[:8]}.\nSign in to {os.getenv('APP_URL', 'http://localhost:8000')}/cases/{case_id} to reply.")
        db.commit()
    return go(f"/cases/{case_id}#conversation")

@app.post("/cases/{case_id}/checkout")
async def checkout(request: Request, case_id: str):
    form = await request.form()
    check_csrf(request, form)
    plan = str(form.get("plan", ""))
    if plan not in PLANS:
        raise HTTPException(400, "Unknown plan")
    if not os.getenv("STRIPE_SECRET_KEY"):
        return go(f"/cases/{case_id}", error="Online checkout is not configured yet")
    with SessionLocal() as db:
        user = require_user(request, db)
        item = get_case(db, case_id, user)
        if item.user_id != user.id:
            raise HTTPException(403, "Only the case owner can pay")
        if not item.ownership_verified or item.status == "CLOSED" or feasibility_state(db, item) != "ELIGIBLE":
            return go(f"/cases/{case_id}", error="Ownership and technical feasibility reviews are required before checkout")
        if db.scalar(select(Order).where(Order.case_id == case_id, Order.plan == plan, Order.status == "PAID")):
            return go(f"/cases/{case_id}", error="This service is already paid for")
        order = Order(user_id=user.id, case_id=item.id, plan=plan, amount_cents=PLANS[plan]["amount"])
        db.add(order)
        db.commit()
        try:
            session = await start_checkout(order=order, user=user, case=item, request=request)
        except Exception:
            order.status = "FAILED"
            db.commit()
            return go(f"/cases/{case_id}", error="Checkout could not be started; please try again")
        order.stripe_session_id = session["id"]
        db.commit()
        return RedirectResponse(session["url"], status_code=303)

@app.get("/checkout/success", response_class=HTMLResponse)
def payment_success(request: Request):
    with SessionLocal() as db:
        if not get_user(request, db): return go("/login")
    return render(request, "checkout.html", active="dashboard")

@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    raw = await request.body()
    try:
        event = validate_webhook(raw, request.headers.get("stripe-signature", ""))
    except (ValueError, KeyError):
        raise HTTPException(400, "Invalid webhook signature or payload")
    event_id = str(event.get("id", ""))
    if not event_id:
        raise HTTPException(400, "Missing event ID")
    with SessionLocal() as db:
        if db.get(StripeEvent, event_id):
            return {"received": True, "duplicate": True}
        if event.get("type") == "checkout.session.completed":
            session = event.get("data", {}).get("object", {})
            order_id = session.get("metadata", {}).get("order_id")
            order = db.get(Order, order_id) if order_id else None
            if order and session.get("payment_status") == "paid" and (
                session.get("amount_total") == order.amount_cents and
                session.get("currency") == "usd" and
                session.get("id") and order.stripe_session_id in (None, session.get("id")) and
                session.get("client_reference_id") == order.id and
                order.status == "PENDING"
            ):
                order.stripe_session_id = session["id"]
                order.status = "PAID"
                audit(db, order.user_id, "payment_confirmed", order.id)
        db.add(StripeEvent(id=event_id))
        db.commit()
    return {"received": True}

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    with SessionLocal() as db:
        user = get_user(request, db)
        if not user: return go("/login")
        require_admin(request, db)
        cases = db.scalars(select(RecoveryCase).options(selectinload(RecoveryCase.user)).order_by(RecoveryCase.created_at.desc()).limit(150)).all()
        orders = db.scalars(select(Order).options(selectinload(Order.user)).order_by(Order.created_at.desc()).limit(60)).all()
        devices = db.scalars(select(DeviceRecord).options(selectinload(DeviceRecord.user)).order_by(DeviceRecord.created_at.desc()).limit(150)).all()
        stats = {"devices": db.scalar(select(func.count(DeviceRecord.id))),
                 "cases": db.scalar(select(func.count(RecoveryCase.id))),
                 "pending": db.scalar(select(func.count(RecoveryCase.id)).where(RecoveryCase.status == "REVIEW")),
                 "verified": db.scalar(select(func.count(RecoveryCase.id)).where(RecoveryCase.ownership_verified == True)),
                 "paid": db.scalar(select(func.coalesce(func.sum(Order.amount_cents), 0)).where(Order.status == "PAID"))}
        reviews = db.scalars(select(FeasibilityReview).where(FeasibilityReview.case_id.in_([c.id for c in cases]))).all()
        feasibility_map = {r.case_id: r.state for r in reviews}
        return render(request, "admin.html", cases=cases, devices=devices, orders=orders,
                      feasibility_map=feasibility_map, stats=stats, active="admin")

@app.post("/admin/cases/{case_id}/update")
async def admin_update(request: Request, case_id: str, tasks: BackgroundTasks):
    form = await request.form()
    check_csrf(request, form)
    status = str(form.get("status", ""))
    verified = form.get("ownership_verified") == "yes"
    feasibility_choice = str(form.get("feasibility", ""))
    feasibility_notes = str(form.get("feasibility_notes", "")).strip()
    if status not in STATUSES:
        raise HTTPException(400, "Unknown status")
    if feasibility_choice and feasibility_choice not in {"PENDING", "ELIGIBLE", "INELIGIBLE"}:
        raise HTTPException(400, "Invalid feasibility review")
    if len(feasibility_notes) > 500:
        raise HTTPException(400, "Technical review note is too long")
    with SessionLocal() as db:
        admin = require_admin(request, db)
        item = db.get(RecoveryCase, case_id)
        if not item:
            raise HTTPException(404, "Case not found")
        if status in {"VERIFIED", "IN_PROGRESS", "RESOLVED"} and not verified:
            return go(f"/cases/{case_id}", error="Verify ownership before progressing the case")
        item.status = status
        item.ownership_verified = verified
        if feasibility_choice:
            review = db.get(FeasibilityReview, case_id)
            if not review:
                review = FeasibilityReview(case_id=case_id)
                db.add(review)
            review.state = feasibility_choice
            review.notes = feasibility_notes
            review.reviewed_by = admin.id
            review.reviewed_at = datetime.now(timezone.utc)
        item.updated_at = datetime.now(timezone.utc)
        audit(db, admin.id, "case_updated", item.id)
        destination = db.get(User, item.user_id).email
        db.commit()
        tasks.add_task(send_mail, destination, "Your recovery case was updated",
            f"Your case #{item.id[:8]} status is now {status.replace('_', ' ').title()}.\nReview it at {os.getenv('APP_URL', 'http://localhost:8000')}/cases/{item.id}")
    return go(f"/cases/{case_id}")
