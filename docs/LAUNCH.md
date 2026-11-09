# Launch playbook

## Local acceptance

1. Create Python venv, install requirements, configure `.env`.
2. Run `pytest -q` and verify app starts with `uvicorn app.main:app`.
3. Register a customer; submit one case; confirm the dashboard lists it.
4. Register an admin account; use `scripts/promote_admin.py`; verify `/admin` access.
5. Approve case ownership only after a legitimate verification process.
6. Configure Stripe test keys; verify a test checkout returns to the app and that a correctly signed webhook marks the order paid.
7. Confirm unauthorized users receive 404 on cases they do not own.
8. Test with keyboard, mobile screen readers, and error states.

## Production prerequisites

- Domain / DNS with HTTPS
- Managed PostgreSQL, backups, schema migrations
- Stripe production account, tax/refund settings and webhook endpoint
- Official support contact and reviewed legal text
- Tracing, uptime monitoring, alerting, incident response
- SMTP for password recovery, email verification, admin MFA
- Manual verification process for ownership
- Full security review and load testing

## Docker deployment

Provide a local `.env` with APP_SECRET, APP_URL, POSTGRES_PASSWORD, ADMIN_EMAIL, and optional Stripe keys. Use `docker compose up --build -d`. The service listens on `127.0.0.1:8000`; put a managed HTTPS reverse proxy in front before making it public. Run the admin promotion command inside the web container after customer registration.

## Environments

- **Dev:** SQLite + local Uvicorn; Stripe optional.
- **Staging:** PostgreSQL + Stripe test keys + test domain.
- **Production:** PostgreSQL + Stripe live keys, security controls and operational processes above.

No GitHub Actions are defined. Use a manual deployment or a deployment platform connected directly to GitHub.

## Additional acceptance: two-script and device-payment flow

1. Create a customer case for a test serial; ensure it appears once in `/admin` device registry and only shows serial suffix.
2. Download the free script from `/downloads/mac-check.sh`; confirm it prints local device details and asks consent before making any network call.
3. From the case page issue a CHECK code; verify `REVIEW_REQUIRED`. Check that using it twice fails and that the wrong serial fails without revealing account/payment information.
4. Admin verifies ownership; new CHECK code should report `FEASIBILITY_REVIEW` until a separate technical review approves the read-only support service. Then it reports `PAYMENT_REQUIRED` before checkout.
5. Complete Stripe test checkout and deliver a signed, paid `checkout.session.completed` webhook. Confirm `PAID` state now appears on a fresh CHECK after both reviews are approved.
6. Confirm the support script is **403 Forbidden** before payment, and downloadable afterward to the case owner or via the paid checker's separate one-time handoff code. Verify the download checksum and confirm a second request with the same code fails. Issue a fresh SUPPORT code and verify only one successful support authorization.
7. Revoke ownership approval (or close case); verify support kit download and support execution are both blocked again.
8. Confirm no public page exposes the former company's full legal name. Brand is **AHT Revive** only; legal and merchant disclosures still need compliance review.

**Deployment warning:** If upgrading an existing DB, back up the DB before introducing new `device_records` / `device_access_grants` tables and backfill canonical device records from existing `recovery_cases` where appropriate. Never change APP_SECRET casually; it is currently also the HMAC fingerprint key.
