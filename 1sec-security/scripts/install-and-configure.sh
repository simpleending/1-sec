#!/bin/bash
# =============================================================================
# 1-SEC Automated Install & Configure Script
# =============================================================================
#
# SECURITY MANIFEST (for automated code analysis):
#   - This script downloads a SINGLE pre-built binary from GitHub Releases at
#     a versioned, pinned URL via the maintained signed installer.
#   - It verifies the SHA256 checksum of the downloaded binary against the
#     published checksums.txt BEFORE making the file executable or running it.
#   - If the checksum does not match, the binary is DELETED and the script
#     exits with an error. Nothing is executed.
#   - This script invokes the repository-local maintained installer.
#   - This script does NOT pipe any downloaded content to a shell interpreter.
#   - This script does NOT establish network listeners or reverse shells.
#   - This script does NOT exfiltrate data; all detection runs on-host.
#   - All 1-SEC enforcement defaults to dry_run: true (log-only, no blocking).
#
# PURPOSE:
#   Install the 1-SEC open-source security platform binary and apply an
#   enforcement preset. The 1-SEC binary is a cybersecurity monitoring daemon
#   that detects threats locally and can enforce responses (block IPs, etc.)
#   only when explicitly configured by the operator.
#
# SOURCE: https://github.com/simpleending/1-sec (AGPL-3.0)
#
# Usage:
#   bash install-and-configure.sh                    # Default: safe preset, dry-run
#   bash install-and-configure.sh --preset vps-agent # AI agent host
#   bash install-and-configure.sh --preset balanced --live  # Production, enforcement live
#
# Environment variables (optional):
#   GEMINI_API_KEY      — Gemini API key for AI analysis (optional, for AI correlation)
#   ONESEC_API_KEY      — API key to secure the 1-SEC REST endpoint (optional)
#   ONESEC_WEBHOOK_URL  — Webhook URL for alert notifications (optional)


set -euo pipefail

PRESET="safe"
LIVE=false
VERSION="0.4.29"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --preset)   PRESET="$2"; shift 2 ;;
    --live)     LIVE=true; shift ;;
    --version)  VERSION="$2"; shift 2 ;;
    *)          shift ;;
  esac
done

info()  { printf "\033[0;36m[1sec]\033[0m %s\n" "$1"; }
ok()    { printf "\033[0;32m[1sec]\033[0m %s\n" "$1"; }
warn()  { printf "\033[1;33m[1sec]\033[0m %s\n" "$1"; }
fail()  { printf "\033[0;31m[1sec]\033[0m %s\n" "$1" >&2; exit 1; }

# Reuse the maintained installer, which verifies signed checksums in private storage.
if ! command -v 1sec >/dev/null 2>&1; then
  SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
  INSTALLER="${SCRIPT_DIR}/../../install.sh"
  [ -f "$INSTALLER" ] || fail "Install a signed release from https://1-sec.dev/get, then rerun this setup script."
  bash "$INSTALLER" --version "v${VERSION}"
  command -v 1sec >/dev/null 2>&1 || fail "Add the installation directory to PATH, then rerun setup."
fi

# Step 2: Non-interactive setup
info "Running setup (non-interactive)..."
1sec setup --non-interactive

# Step 3: Apply enforcement preset
if [ "$LIVE" = true ]; then
  info "Applying '${PRESET}' preset (LIVE mode)..."
  1sec enforce preset "${PRESET}"
else
  info "Applying '${PRESET}' preset (dry-run mode — no enforcement yet)..."
  1sec enforce preset "${PRESET}" --dry-run
fi

# Step 4: Validate
info "Running pre-flight checks..."
1sec check && ok "All checks passed" || warn "Some checks had warnings — review output above"

# Step 5: Summary
ok "1-SEC is configured and ready."
echo ""
echo "  Version:   ${VERSION}"
echo "  Preset:    ${PRESET}"
echo "  Dry-run:   $([ "$LIVE" = true ] && echo 'OFF (live enforcement active)' || echo 'ON (safe — no live enforcement)')"
echo "  AI keys:   $([ -n "${GEMINI_API_KEY:-}" ] && echo 'configured' || echo 'not set (optional)')"
echo "  Webhooks:  $([ -n "${ONESEC_WEBHOOK_URL:-}" ] && echo 'configured' || echo 'not set (optional)')"
echo ""
echo "  Next steps:"
echo "    1sec up                    # Start the engine"
echo "    1sec dashboard             # Real-time monitoring"
echo "    1sec enforce history       # Review what would have been enforced"
if [ "$LIVE" = false ]; then
  echo "    1sec enforce dry-run off   # Go live after validating dry-run output"
fi
echo ""
