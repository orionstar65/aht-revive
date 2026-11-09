#!/bin/bash
# AHT Revive Stage 2 — paid, authorized, read-only support diagnostics.
# Never modifies enrollment settings, disables security controls, or injects users.
set -u
say() { printf '%s\n' "$*"; }
api_base="${AHT_API_URL:-https://example.invalid}"
case "$api_base" in
  https://*) curl_proto="=https" ;;
  http://127.0.0.1:*|http://localhost:*) curl_proto="=http,https" ;;
  *) say "ERROR: AHT_API_URL must be HTTPS (localhost HTTP permitted for tests)."; exit 1 ;;
esac
api_base="${api_base%/}"
serial="$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | sed -n 's/.*"IOPlatformSerialNumber" = "\([^"]*\)".*/\1/p' | head -n 1)"
serial="$(printf '%s' "$serial" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
if ! printf '%s' "$serial" | grep -Eq '^[A-Z0-9]{6,24}$'; then
  say "No valid serial detected. Diagnostics were not started."
  exit 1
fi
say "================================================"
say " AHT Revive | Authorized Support Diagnostics"
say "================================================"
say "Serial: $serial"
say "This script collects read-only disk and system information."
say "The report remains locally on this Mac unless you choose to share it."
printf 'Continue? [y/N] '
IFS= read -r answer
case "$answer" in y|Y|yes|YES) ;; *) exit 0;; esac
printf 'Case ID: '
IFS= read -r case_id
printf 'Fresh one-time SUPPORT code: '
IFS= read -r -s code
printf '\n'
if [ -z "$case_id" ] || [ -z "$code" ]; then say 'Missing case ID or code.'; exit 1; fi
response="$(curl --silent --show-error --fail --max-time 25 --proto "$curl_proto" \
  -X POST "$api_base/api/v1/device/support-authorization" \
  --data-urlencode "case_id=$case_id" \
  --data-urlencode "access_code=$code" \
  --data-urlencode "serial=$serial")"
rc=$?
code=""
if [ "$rc" -ne 0 ] || [ "$response" != "$(printf 'STATE=AUTHORIZED\nDETAIL=Read-only diagnostics may proceed.')" ]; then
  say "Authorization denied or unavailable. No diagnostics executed."
  exit 1
fi
umask 077
report="$(mktemp /tmp/aht-revive-diagnostics.XXXXXX)" || exit 1
{
  say "AHT Revive — read-only diagnostic report"
  say "Created (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  say "Serial suffix: ${serial: -4}"
  say "================================================"
  say "Operating system / runtime"
  sw_vers 2>&1 || true
  say "================================================"
  say "Disks"
  diskutil list 2>&1 || true
  say "================================================"
  say "APFS container structure"
  diskutil apfs list 2>&1 || true
  say "================================================"
  say "FileVault"
  fdesetup status 2>&1 || true
  say "================================================"
  say "System Integrity Protection"
  csrutil status 2>&1 || true
  say "================================================"
  say "Enrollment status (informational only)"
  profiles status -type enrollment 2>&1 || true
} > "$report"
say ""
say "Report saved locally: $report"
say "It may contain volume names or device configuration details. Review it before sharing."
say "No MDM settings, user accounts or system files were modified."
