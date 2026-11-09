#!/bin/bash
# AHT Revive Stage 1 — read-only hardware identification & case status.
# This tool makes no changes to macOS, management enrollment, or user accounts.
set -u

say() { printf '%s\n' "$*"; }
api_base="${AHT_API_URL:-https://example.invalid}"
case "$api_base" in
  https://*) curl_proto="=https" ;;
  http://127.0.0.1:*|http://localhost:*) curl_proto="=http,https" ;;
  *) say "ERROR: AHT_API_URL must be an HTTPS URL (local dev may use localhost HTTP)."; exit 1 ;;
esac
api_base="${api_base%/}"

serial=""
if command -v ioreg >/dev/null 2>&1; then
  serial="$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | sed -n 's/.*"IOPlatformSerialNumber" = "\([^"]*\)".*/\1/p' | head -n 1)"
fi
if [ -z "$serial" ] && command -v system_profiler >/dev/null 2>&1; then
  serial="$(system_profiler SPHardwareDataType 2>/dev/null | awk -F ': ' '/Serial Number \(system\)/ {print $2; exit}')"
fi
serial="$(printf '%s' "$serial" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
model="$(sysctl -n hw.model 2>/dev/null || true)"
arch="$(uname -m 2>/dev/null || true)"
chip="Unknown (Recovery may not report the chip)"
if command -v system_profiler >/dev/null 2>&1; then
  detected="$(system_profiler SPHardwareDataType 2>/dev/null | awk -F ': ' '/^[[:space:]]*(Chip|Processor Name):/ {print $2; exit}')"
  [ -z "$detected" ] || chip="$detected"
fi
runtime_os="$(sw_vers -productVersion 2>/dev/null || true)"

say "================================================"
say " AHT Revive | Mac Identification & Eligibility"
say "================================================"
say "Device model ID : ${model:-Unavailable}"
say "Architecture    : ${arch:-Unavailable}"
say "Processor       : $chip"
say "Serial number   : ${serial:-Unavailable}"
say "Runtime macOS   : ${runtime_os:-Unavailable} (may be Recovery OS)"
say ""
say "The tool only reads device information. Remote eligibility is a"
say "preliminary case status, not proof of permanent MDM release."
say ""
if ! printf '%s' "$serial" | grep -Eq '^[A-Z0-9]{6,24}$'; then
  say "Unable to read a valid serial. Open a case through the website instead."
  exit 1
fi
printf 'Send this serial and case code over HTTPS to check eligibility? [y/N] '
IFS= read -r confirm
case "$confirm" in y|Y|yes|YES) ;; *) say "No details transmitted."; exit 0;; esac
printf 'Case ID (from your signed-in dashboard): '
IFS= read -r case_id
printf 'One-time CHECK code (from your dashboard): '
IFS= read -r -s code
printf '\n'
if [ -z "$case_id" ] || [ -z "$code" ]; then say "Missing case ID or code."; exit 1; fi
say "Checking case eligibility and payment status..."
response="$(curl --silent --show-error --fail --max-time 25 --proto "$curl_proto" \
  -X POST "$api_base/api/v1/device/check" \
  --data-urlencode "case_id=$case_id" \
  --data-urlencode "access_code=$code" \
  --data-urlencode "serial=$serial")"
rc=$?
code=""
if [ "$rc" -ne 0 ]; then
  say "Check failed (invalid/expired code, serial mismatch, or network issue)."
  say "Return to your case dashboard for a new code."
  exit 1
fi
state="$(printf '%s\n' "$response" | sed -n 's/^STATE=//p' | head -n 1)"
detail="$(printf '%s\n' "$response" | sed -n 's/^DETAIL=//p' | head -n 1)"
kit_code="$(printf '%s\n' "$response" | sed -n 's/^KIT_CODE=//p' | head -n 1)"
kit_digest="$(printf '%s\n' "$response" | sed -n 's/^KIT_SHA256=//p' | head -n 1)"
say ""
say "Status: $state"
say "$detail"
say ""
if [ "$state" = "PAID" ] && [ -n "$kit_code" ] && printf '%s' "$kit_digest" | grep -Eq '^[a-f0-9]{64}$'; then
  printf 'Download the protected read-only support script for inspection? [y/N] '
  IFS= read -r next_step
  case "$next_step" in
    y|Y|yes|YES)
      # The backend checks the code, matching serial, ownership, feasibility and payment again.
      # Save only; never execute newly downloaded code without user inspection.
      target="$(mktemp /tmp/aht-revive-support.XXXXXXXX)" || exit 1
      if ! curl --silent --show-error --fail --max-time 30 --proto "$curl_proto" \
           -X POST "$api_base/api/v1/device/kit" \
           --data-urlencode "case_id=$case_id" \
           --data-urlencode "access_code=$kit_code" \
           --data-urlencode "serial=$serial" -o "$target"; then
        rm -f "$target"
        say "The support kit could not be downloaded. Use your dashboard to try again."
        exit 1
      fi
      actual_digest="$(shasum -a 256 "$target" 2>/dev/null | awk '{print $1}')"
      if [ "$actual_digest" != "$kit_digest" ]; then
        rm -f "$target"
        say "Support kit integrity check failed; the file has been deleted."
        exit 1
      fi
      chmod 700 "$target"
      say "Verified SHA-256: $actual_digest"
      say "Support tool downloaded to: $target"
      say "Inspect the entire file before choosing to execute it."
      say "A fresh one-time SUPPORT code is required from the signed-in case dashboard."
      ;;
    *) say "No support script downloaded." ;;
  esac
else
  say "Sign in to your case dashboard for your next step."
fi
