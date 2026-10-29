#!/usr/bin/env bash
set -Eeuo pipefail

REPO="KilluaAoki/XNode"
VERSION="latest"
BINARY=""
ARGS=()

red() { printf '\033[0;31m%s\033[0m\n' "$1"; }
green() { printf '\033[0;32m%s\033[0m\n' "$1"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --binary)
            BINARY="$2"
            shift 2
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    red "Please run as root or with sudo"
    exit 1
fi

INSTALLED="/usr/local/bin/xnode"

has_tty() {
    { true </dev/tty; } 2>/dev/null
}

with_tty() {
    if has_tty; then
        "$@" </dev/tty
    else
        "$@"
    fi
}

if [ ${#ARGS[@]} -eq 0 ] && [ -z "$BINARY" ] && [ "$VERSION" = "latest" ] && [ -x "$INSTALLED" ] && has_tty; then
    exec "$INSTALLED" menu </dev/tty
fi

case "$(uname -s)" in
    Linux) OS="linux" ;;
    Darwin) OS="macos" ;;
    *)
        red "Unsupported OS: $(uname -s)"
        exit 1
        ;;
esac

case "$(uname -m)" in
    x86_64 | amd64) ARCH="64" ;;
    aarch64 | arm64) ARCH="arm64-v8a" ;;
    armv7* | armv8l) ARCH="arm32-v7a" ;;
    *)
        red "Unsupported architecture: $(uname -m)"
        exit 1
        ;;
esac

if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl unzip ca-certificates
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q curl unzip ca-certificates
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q curl unzip ca-certificates
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache -q curl unzip ca-certificates
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm curl unzip ca-certificates
    else
        red "curl and unzip are required"
        exit 1
    fi
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
STAGED="$TMP_DIR/xnode"

if [ -n "$BINARY" ]; then
    cp "$BINARY" "$STAGED"
else
    ASSET="xnode-${OS}-${ARCH}.zip"
    if [ "$VERSION" = "latest" ]; then
        URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
    else
        URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
    fi
    green "Downloading ${URL}"
    curl -fL --retry 3 --connect-timeout 15 -o "$TMP_DIR/$ASSET" "$URL"
    unzip -o -q "$TMP_DIR/$ASSET" xnode -d "$TMP_DIR"
fi

chmod +x "$STAGED"
if [ "$OS" = "macos" ]; then
    xattr -d com.apple.quarantine "$STAGED" >/dev/null 2>&1 || true
fi
"$STAGED" version

ACTION="install"
if [ ${#ARGS[@]} -gt 0 ]; then
    case "${ARGS[0]}" in
        install | upgrade | uninstall)
            ACTION="${ARGS[0]}"
            ARGS=("${ARGS[@]:1}")
            ;;
    esac
fi

case "$ACTION" in
    upgrade) with_tty "$STAGED" upgrade --from "$STAGED" ;;
    *) with_tty "$STAGED" "$ACTION" ${ARGS[@]+"${ARGS[@]}"} ;;
esac
