# Security and compliance review

Implemented baseline:

- Argon2id password hashing, session token randomization, database-hashed tokens, seven-day session expiry, HttpOnly cookie, SameSite Lax, and optional Secure cookies enforced in production.
- Signed CSRF double-submit cookie on all mutating HTML forms; no state modification through GET.
- Access-controlled case reads and writes, administrator role checks, bounded field lengths, audit entries for review changes.
- CSP, clickjacking and MIME protections; no third-party JavaScript on the website.
- Basic persistent per-email failed-login rate limiting (8 attempts / 15 minutes).
- Stripe webhook signature verification, 5-minute replay bound, event ID idempotency.
- Server-owned prices, ownership review before checkout, no payment status inferred from redirect.

Required before public commercial launch:

1. **Ownership workflow:** define proof standards and a secure channel for review. A reference string alone is not proof of ownership.
2. **Identity & email:** verify account emails, configure SMTP delivery for one-time password reset links, and add admin MFA.
3. **Migrations:** use Alembic and explicit deployment migration steps rather than `create_all`.
4. **Distributed abuse prevention:** account/IP rate-limits across replicas, bot protections, monitoring of abnormal cases.
5. **Data protection:** key-management plan for serial HMAC fingerprinting, retention/deletion schedule, privacy request process, documented encryption and backup policy.
6. **Payment operations:** refund process, dispute handling, receipts, VAT/sales-tax handling as applicable, and payment event reconciliation.
7. **Infrastructure:** production TLS, reverse-proxy trust configuration, verified webhook endpoint, backups, independent pen test, request timeouts.
8. **Legal:** have qualified counsel review service terms, privacy policy, refund policy, jurisdiction-specific consumer laws and authorized-use policy.
9. **Operational:** support notifications and service-level expectations, secrets rotation, audit export and alerting.
10. **Release:** avoid any claim that local device changes constitute official removal from Apple Business Manager.

The site is intentionally scoped to diagnosis and authorized customer support. Do not add unattended recovery-time remote code execution or tooling that bypasses another organization's security controls.

## Mac-check and paid-kit safeguards

- No public serial-only payment lookup. The first stage requires a short-lived case-scoped CHECK code issued through an authenticated session.
- One-time access grants use random bearer secrets hashed in the DB; no code plaintext is persisted. Code issuance is bounded per account and hour.
- `/cases/{id}/download-support` is not a public static asset. Every GET verifies the owner, manual ownership approval, confirmed payment, and open case state.
- The second stage checks the case and payment again before collecting read-only local diagnostics. It does not download or execute arbitrary server-provided shell commands.
- Neither stage changes `/etc/hosts`, MDM enrollment, setup flags, or local accounts.
- Current serial confirmation is **client claimed** and therefore spoofable: do not treat it as cryptographic hardware attestation.
- Refunds/chargebacks, device-ownership transfers, tamper-resistant delivery, cancellation, and production rate limiting remain future work.

- A paid `CHECK` response mints a separate one-time `KIT_DOWNLOAD` token and a checksum for the paid diagnostic script. The free checker asks for explicit download consent, validates the SHA-256 digest, and **does not auto-execute** a downloaded script.
