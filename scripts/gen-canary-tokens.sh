#!/usr/bin/env bash
#
# gen-canary-tokens.sh — generate fresh FAKE JWT / API tokens for the
# config-secrets decoy, using `openssl rand`.
#
# Everything printed is a RANDOM decoy (no real secrets). Paste the ones you
# want into config/canary.json ("jwt_secret" / "api_token"), then restart the
# sensor so the decoy reloads. Rotating these per deployment keeps the served
# bait values unique and private (canary.json is gitignored).
#
# Usage:  ./scripts/gen-canary-tokens.sh
#
set -euo pipefail

command -v openssl >/dev/null 2>&1 || { echo "openssl not found in PATH" >&2; exit 1; }

# base64url (no padding) of stdin
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# --- JWT signing secret (what the decoy's "jwt_secret" field holds) ---
jwt_secret="$(openssl rand -base64 48 | tr -d '\n')"

# --- a full, realistic-looking fake JWT: header.payload.signature ---
now="$(date +%s)"
jwt_header="$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64url)"
jwt_payload="$(printf '{"sub":"svc_app","iss":"auth.internal","role":"service","iat":%s,"exp":%s}' "$now" "$((now + 3600))" | b64url)"
jwt_sig="$(openssl rand 32 | b64url)"
jwt_token="${jwt_header}.${jwt_payload}.${jwt_sig}"

# --- API-style tokens ---
api_stripe="sk_live_$(openssl rand -hex 24)"
api_generic="$(openssl rand -hex 32)"
rails_secret="$(openssl rand -hex 64)"

cat <<EOF
# Fresh fake decoy tokens ($(date -u +%Y-%m-%dT%H:%M:%SZ)) — all random, safe to plant.

JWT signing secret : ${jwt_secret}
Full fake JWT      : ${jwt_token}
Stripe-style API   : ${api_stripe}
Generic API key    : ${api_generic}
Rails secret_key   : ${rails_secret}

# Paste into config/canary.json, then restart the sensor:
  "jwt_secret": "${jwt_secret}",
  "api_token": "${api_stripe}",
EOF
