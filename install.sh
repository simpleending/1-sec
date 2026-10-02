#!/bin/sh
# 1-SEC Installer
# Usage:
#   curl -fsSL https://1-sec.dev/get | sh
#   curl -fsSL https://1-sec.dev/get | sh -s -- --version v1.2.3
#
# Detects OS/arch, downloads a signed GitHub release artifact, verifies the
# checksum bundle with Sigstore/cosign, and installs the 1sec binary to
# /usr/local/bin (or ~/.local/bin if no root access).

set -e

REPO="simpleending/1-sec"
BINARY="1sec"
INSTALL_DIR="/usr/local/bin"
VERSION="${ONESEC_VERSION:-}"
VERIFY="1"

# Colors (if terminal supports it)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { printf "${CYAN}[1sec]${NC} %s\n" "$1"; }
ok()    { printf "${GREEN}[1sec]${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}[1sec]${NC} %s\n" "$1"; }
fail()  { printf "${RED}[1sec]${NC} %s\n" "$1" >&2; exit 1; }

usage() {
    cat <<EOF
1SEC installer

Options:
  --version <tag>   Install an explicit release tag, e.g. v1.2.3.
  --no-verify       Skip cosign/checksum verification (not recommended).
  --help            Show this help.

Environment:
  ONESEC_VERSION    Install an explicit release tag.
EOF
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)   echo "linux" ;;
        Darwin*)  echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *)        fail "Unsupported OS: $(uname -s)" ;;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        *)              fail "Unsupported architecture: $(uname -m)" ;;
    esac
}

# Get latest release tag from GitHub API
get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
    else
        fail "Neither curl nor wget found. Please install one and try again."
    fi
}

# Download a URL to a file
download() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        fail "Neither curl nor wget found. Please install one and try again."
    fi
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version)
                [ "$#" -ge 2 ] || fail "--version requires a value"
                VERSION="$2"
                shift 2
                ;;
            --no-verify)
                VERIFY="0"
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                fail "Unknown option: $1"
                ;;
        esac
    done
}

normalize_version() {
    v="$1"
    case "$v" in
        v*) echo "$v" ;;
        *)  echo "v$v" ;;
    esac
}

verify_release_artifact() {
    archive="$1"
    tmp_dir="$2"
    checksums="${tmp_dir}/checksums.txt"
    bundle="${tmp_dir}/checksums.txt.sigstore.json"

    if [ "$VERIFY" = "0" ]; then
        warn "Skipping release verification because --no-verify was provided."
        return
    fi

    command -v cosign >/dev/null 2>&1 || fail "cosign is required to verify releases. Install cosign or rerun with --no-verify only if you trust this network and release."

    info "Downloading signed checksums..."
    download "https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt" "$checksums"
    download "https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt.sigstore.json" "$bundle"

    info "Verifying checksum signature..."
    cosign verify-blob \
        --bundle "$bundle" \
        --certificate-identity-regexp "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/.*" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "$checksums" >/dev/null

    info "Verifying archive checksum..."
    checksum_line=$(grep "[[:space:]]${archive}$" "$checksums" || true)
    [ -n "$checksum_line" ] || fail "Archive ${archive} not found in checksums.txt"
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$tmp_dir" && printf "%s\n" "$checksum_line" | sha256sum -c - >/dev/null)
    elif command -v shasum >/dev/null 2>&1; then
        expected=$(printf "%s\n" "$checksum_line" | awk '{print $1}')
        actual=$(shasum -a 256 "${tmp_dir}/${archive}" | awk '{print $1}')
        [ "$expected" = "$actual" ] || fail "Checksum verification failed for ${archive}"
    else
        fail "Neither sha256sum nor shasum found. Cannot verify ${archive}."
    fi
}

main() {
    parse_args "$@"

    info "Detecting system..."
    OS=$(detect_os)
    ARCH=$(detect_arch)
    info "OS: ${OS}, Arch: ${ARCH}"

    if [ -z "$VERSION" ]; then
        info "Fetching latest release..."
        VERSION=$(get_latest_version)
    else
        VERSION=$(normalize_version "$VERSION")
        info "Requested version: ${VERSION}"
    fi
    if [ -z "$VERSION" ]; then
        fail "Could not determine latest version. Check https://github.com/${REPO}/releases"
    fi
    # Strip leading 'v' for the archive name
    VERSION_NUM=$(echo "$VERSION" | sed 's/^v//')
    info "Latest version: ${VERSION}"

    # Build download URL (matches GoReleaser naming)
    if [ "$OS" = "windows" ]; then
        ARCHIVE="1sec_${VERSION_NUM}_${OS}_${ARCH}.zip"
    else
        ARCHIVE="1sec_${VERSION_NUM}_${OS}_${ARCH}.tar.gz"
    fi
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"

    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    info "Downloading ${ARCHIVE}..."
    download "$URL" "${TMP_DIR}/${ARCHIVE}"

    verify_release_artifact "$ARCHIVE" "$TMP_DIR"

    info "Extracting..."
    if [ "$OS" = "windows" ]; then
        unzip -q "${TMP_DIR}/${ARCHIVE}" -d "$TMP_DIR"
    else
        tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "$TMP_DIR"
    fi

    # Determine install location
    if [ -w "$INSTALL_DIR" ]; then
        TARGET="$INSTALL_DIR"
    elif [ "$(id -u)" = "0" ]; then
        TARGET="$INSTALL_DIR"
    else
        TARGET="${HOME}/.local/bin"
        mkdir -p "$TARGET"
        warn "No root access. Installing to ${TARGET}"
        warn "Make sure ${TARGET} is in your PATH."
    fi

    # Install
    cp "${TMP_DIR}/${BINARY}" "${TARGET}/${BINARY}"
    chmod +x "${TARGET}/${BINARY}"

    ok "Installed 1sec ${VERSION} to ${TARGET}/${BINARY}"
    echo ""
    info "Get started:"
    echo "  ${BINARY} up        # Start all defense modules"
    echo "  ${BINARY} status    # Check engine status"
    echo "  ${BINARY} modules   # List all modules"
    echo "  ${BINARY} collect   # Start log collectors (nginx, auth, pfsense, json, github)"
    echo "  ${BINARY} archive   # Manage cold archive (status, list, restore)"
    echo "  ${BINARY} enforce   # Manage automated threat response"
    echo ""
    ok "Done. Stay secure."
}

main "$@"
