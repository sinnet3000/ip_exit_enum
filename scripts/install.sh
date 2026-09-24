#!/bin/bash
# ip_exit_enum installer
# Usage: curl -fsSL https://raw.githubusercontent.com/sinnet3000/ip_exit_enum/main/scripts/install.sh | bash

set -e

REPO="sinnet3000/ip_exit_enum"
BINARY_NAME="ip_exit_enum"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}$1${NC}"; }
warn() { echo -e "${YELLOW}$1${NC}"; }
error() { echo -e "${RED}$1${NC}" >&2; exit 1; }

detect_os() {
    case "$(uname -s)" in
        Darwin) echo "darwin" ;;
        Linux) echo "linux" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) error "Unsupported OS: $(uname -s)" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7*|armhf) echo "arm" ;;
        *) error "Unsupported architecture: $(uname -m)" ;;
    esac
}

find_install_dir() {
    if [ -w "/usr/local/bin" ]; then
        echo "/usr/local/bin"
    else
        mkdir -p "$HOME/.local/bin"
        echo "$HOME/.local/bin"
    fi
}

download() {
    local url="$1"
    local output="$2"
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget &>/dev/null; then
        wget -q "$url" -O "$output"
    else
        error "Neither curl nor wget found"
    fi
}

sha256_of() {
    if command -v sha256sum &>/dev/null; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        error "Neither sha256sum nor shasum found; cannot verify download"
    fi
}

verify_checksum() {
    local archive="$1" sums="$2" filename="$3"
    local expected=$(awk -v f="$filename" '{n=$2; sub(/^\*/, "", n)} n==f {print $1; exit}' "$sums")
    [ -n "$expected" ] || error "No checksum listed for ${filename}"
    local actual=$(sha256_of "$archive")
    [ "$expected" = "$actual" ] || error "Checksum mismatch for ${filename}: expected ${expected}, got ${actual}"
}

get_latest_version() {
    local url="https://api.github.com/repos/${REPO}/releases/latest"
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" | grep '"tag_name"' | head -1 | cut -d'"' -f4
    elif command -v wget &>/dev/null; then
        wget -qO- "$url" | grep '"tag_name"' | head -1 | cut -d'"' -f4
    fi
}

main() {
    info "Installing ${BINARY_NAME}..."
    echo

    local os=$(detect_os)
    local arch=$(detect_arch)
    local install_dir=$(find_install_dir)

    info "Platform: ${os}/${arch}"
    info "Install directory: ${install_dir}"
    echo

    info "Fetching latest release..."
    local ver=$(get_latest_version)

    if [ -z "$ver" ]; then
        error "Could not determine latest version"
    fi

    info "Found version: $ver"

    local version="${ver#v}"
    local filename="${BINARY_NAME}_${version}_${os}_${arch}.tar.gz"
    local url="https://github.com/${REPO}/releases/download/${ver}/${filename}"

    local tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    info "Downloading ${filename}..."
    if ! download "$url" "$tmpdir/release.tar.gz"; then
        error "Download failed. Check https://github.com/${REPO}/releases for available binaries."
    fi

    info "Verifying checksum..."
    if ! download "https://github.com/${REPO}/releases/download/${ver}/SHA256SUMS" "$tmpdir/SHA256SUMS"; then
        error "Could not download SHA256SUMS; refusing to install an unverified binary."
    fi
    verify_checksum "$tmpdir/release.tar.gz" "$tmpdir/SHA256SUMS" "$filename"

    info "Extracting..."
    tar -xzf "$tmpdir/release.tar.gz" -C "$tmpdir"

    local bin="${BINARY_NAME}"
    [ "$os" = "windows" ] && bin="${BINARY_NAME}.exe"

    if [ -w "$install_dir" ]; then
        mv "$tmpdir/$bin" "$install_dir/"
    else
        sudo mv "$tmpdir/$bin" "$install_dir/"
    fi
    chmod +x "$install_dir/$bin"

    if [ "$os" = "darwin" ]; then
        codesign -s - "$install_dir/${BINARY_NAME}" 2>/dev/null || true
    fi

    echo
    info "Installation complete! ${BINARY_NAME} ${ver}"
    echo

    if ! echo "$PATH" | grep -q "$install_dir"; then
        warn "Add this to your shell profile:"
        echo "  export PATH=\"\$PATH:$install_dir\""
        echo
    fi

    echo "Run it:"
    echo "  ${BINARY_NAME}"
    echo "  ${BINARY_NAME} -v        # verbose"
    echo "  ${BINARY_NAME} -version  # show version"
}

main "$@"
