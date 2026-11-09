# AHT Revive

**Identify your Mac. Verify eligibility. Check payment. Access authorized recovery diagnostics.**

AHT Revive is a FastAPI + PostgreSQL platform with a premium responsive website, accounts, ownership- and feasibility-screened Mac case intake, a canonical device registry keyed by an HMAC fingerprint of each serial, Stripe payments, support messaging, an admin console, and **two separate Mac diagnostic stages**.

**Status:** implemented and locally tested application baseline. Not deployed to production, no payments processed, and not a certified device-management or unlocking service.

> **Scope**: Neither script removes MDM enrollment, disables Apple security services, modifies host files, or injects administrator accounts. Stage 2 is a protected *read-only diagnostic tool*, not a paid MDM bypass payload. Permanent Apple Business enrollment removal remains a separate authorized process. A paid customer can inspect any script supplied to their Mac; client-side scripts cannot be made technically unreadable to recipients.

## Workflow

1. **Register a customer case** with the Mac serial, model and ownership reference. The full serial is transiently processed into an HMAC-SHA256 keyed fingerprint + last four characters; it isn't persisted in plaintext. Duplicate serials in another account need review.
2. **Download the free `mac_check.sh`** after creating your case. It discovers serial, model ID, architecture, processor when available and runtime macOS on the local Mac, displays them **before** asking to transmit anything, and asks for the case ID plus a short-lived, one-time CHECK code from the signed-in case dashboard.
3. **Server-side status** verifies code, serial fingerprint, ownership status, human-approved technical feasibility and confirmed paid orders for that Mac. Returns `REVIEW_REQUIRED`, `FEASIBILITY_REVIEW`, `NOT_ELIGIBLE`, `PAYMENT_REQUIRED`, `PAID`, or `CASE_CLOSED`. A customer-supplied serial is **not** hardware attestation. Technical procedure compatibility must be reviewed separately.
4. **Ownership and technical feasibility reviews** are separate administrator actions; customers cannot approve themselves. Eligibility here only means the case may receive the listed *read-only diagnostic support*, not that arbitrary MDM bypass methods will function.
5. **Checkout**, optional after review, uses Stripe's hosted page. Only the *signed, validated and idempotent* Stripe webhook can mark a payment PAID; redirect alone does nothing. Payment status is scoped to the same user's serial fingerprint across their cases. These are one-time payments, **not auto-renewing subscriptions**.
6. **Paid fulfillment** requires authenticated case ownership, admin-approved ownership and feasibility, an active case and confirmed payment. The second script (`mac_support.sh`) is not exposed by the public static server and is downloadable only through the authenticated protected endpoint. It requests a fresh one-time SUPPORT code, rechecks authorization over HTTPS, and then collects read-only local diagnostics into a private file.

### Access states

```text
Public site → Create account → Register device (HMAC serial registry)
                                ↓
             Free Mac checker → Show local device information
                                ↓ (customer consent + one-time case code)
                  Check API → ownership eligible? → reviewed manually
                                ↓
              Confirm payment from Stripe webhook
                                ↓
     Protected support kit download (authenticated browser
           or one-use paid handoff code from first script)
                                ↓ (SHA-256 verification, no auto-execute)
          Separate support code → second server authorization
                                ↓
              Read-only local diagnostics / support case
```

When the check returns `PAID`, the first script offers to **download** the second script through a one-time server-issued `KIT_DOWNLOAD` capability. It verifies the returned file's SHA-256 digest before keeping it locally and does **not** execute it automatically. The customer inspects the file and then uses a separate dashboard-issued `SUPPORT` code for its own independent authorization check. This is intentional: payment is not authorization to change organizational management controls.

## Quick start

Requirements: Python 3.12+ (web server); macOS shell utilities for the Mac scripts. Run from project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Configure APP_SECRET with a strong stable 32+ char value and APP_URL.
set -a; source .env; set +a
uvicorn app.main:app --reload --port 8000
```

Open `http://localhost:8000`. For the first test, register a customer and open a device case. On the case page choose **Generate check code** and download the free Mac checker. On the Mac:

```bash
# The website offers this file at /downloads/mac-check.sh; inspect it first.
bash ./aht-mac-check.sh
```

When you download via the website, it embeds your configured `APP_URL`; use an HTTPS domain in production. If running a script you copied directly from source, configure the origin first:

```bash
AHT_API_URL=https://your-domain.example bash ./scripts/mac_check.sh
```

In macOS Recovery, some hardware and OS fields may be unavailable. The script reports those limits and does not treat the Recovery operating system's version as the installed system's version.

### Administration

Register an administrator account normally, then bootstrap its role server-side:

```bash
python -m scripts.promote_admin owner@example.com
```

Open `/admin` to see registered devices (suffix only), cases, review statuses, and payment history. A device's case must be approved before paid support can be purchased. Do **not** approve ownership solely based on the serial number or a free-text reference.

### Tests

```bash
pytest -q
bash -n scripts/mac_check.sh scripts/mac_support.sh
```

The test suite covers authentication, case isolation, serial-fingerprint registry, independent eligibility review, device-scoped paid entitlement, one-time code handling, expiry, stage isolation, authorization revocation, protected script delivery, Stripe webhook integrity and idempotency, and password recovery.

## Payments

Set `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `APP_URL`, and configure a Stripe webhook endpoint at `https://your-domain/webhooks/stripe` for `checkout.session.completed`. Payment plans (currently $39 assessment and $99 specialist review) are one-time purchases, not recurring subscriptions. Support-kit entitlement is currently unlocked by *any* confirmed paid order for the same registered Mac and customer. Refunded/disputed payments and device transfers need a future entitlement-revocation workflow before commercial launch.

The success page is informational only. An order stays `PENDING` until a validated webhook is processed.

## Local database and PostgreSQL

SQLite is the default local development database. Production uses PostgreSQL:

```bash
DATABASE_URL=postgresql+psycopg://user:password@host:5432/revive
APP_ENV=production
COOKIE_SECURE=true
APP_SECRET=<at-least-32-random-characters>
APP_URL=https://your-domain.example
```

`docker compose up --build` starts PostgreSQL plus the app locally. Put a TLS reverse proxy or managed HTTPS service in front. **Important:** The first release still uses SQLAlchemy `create_all` to introduce new tables. Use formal schema migrations and a backup before deploying this revision. The additive `device_records`, `device_access_grants` and `feasibility_reviews` tables can be created via the local development bootstrap, but existing production cases need registry backfill with `python -m scripts.backfill_device_registry` (dry-run) and `python -m scripts.backfill_device_registry --apply` after review. Historical cases without a technical review are deliberately `PENDING`. HMAC fingerprints depend on a stable secret: rotating `APP_SECRET` without migration breaks existing device matching.

## Routes

| Path | Purpose | Access |
| --- | --- | --- |
| `/` | AHT Revive website | Public |
| `/register`, `/login`, `/forgot-password` | Account lifecycle | Public |
| `/dashboard`, `/cases/{id}` | Case workspace | Case owner/admin |
| `/admin` | Device, case and order administration | Admin |
| `/downloads/mac-check.sh` | Free read-only Mac identification script | Public |
| `/cases/{id}/access-code` | 15-minute one-time CHECK or SUPPORT code | Case owner; SUPPORT requires paid + reviewed |
| `/api/v1/device/check` | Case-scoped eligibility and payment status | One-time CHECK code, matching Mac serial |
| `/cases/{id}/download-support` | Browser download of separate read-only script | Case owner + ownership/feasibility approved + paid |
| `/api/v1/device/kit` | Checker handoff: separate script download with SHA-256 | One-time KIT_DOWNLOAD code + paid and reviewed serial |
| `/api/v1/device/support-authorization` | Second server check before diagnostics | One-time SUPPORT code, matching serial + reviewed ownership/feasibility + paid |
| `/webhooks/stripe` | Server-signed payment updates | Valid Stripe signature |
| `/healthz` | Health | Public |

## Deploy & operational limitations

The app is a functioning local baseline, **not a production-ready commercial site**. Before accepting customers, implement production Alembic migrations, email verification, admin MFA, distributed rate limits, secure ownership-evidence handling, refund and dispute revocation, payment reconciliation, uptime monitoring, data retention/deletion, and reviewed legal/merchant disclosures. The public website intentionally shows only **AHT Revive**; the actual merchant/registered entity may still have mandatory disclosure obligations on checkout, receipts, and policies.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/SECURITY.md](docs/SECURITY.md), and [docs/LAUNCH.md](docs/LAUNCH.md).

## GitHub publishing

The connected GitHub account is `orionstar65`. The current GitHub connector supports existing-repo edits but **not new repo creation**. To publish this source as a **private** repository, first create `aht-revive` in GitHub under `orionstar65`, then:

```bash
git init -b main
git add .
git commit -m "Build AHT Revive device registry and gated diagnostic flow"
git remote add origin git@github.com:orionstar65/aht-revive.git
git push -u origin main
```

There are no GitHub Actions workflows.