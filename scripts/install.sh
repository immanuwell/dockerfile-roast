#!/usr/bin/env sh
# droast installer
# Usage: curl -fsL ewry.net/droast/install.sh | sh
set -eu

REPO="immanuwell/dockerfile-roast"
BIN="droast"
INSTALL_DIR="/usr/local/bin"

# ── helpers ────────────────────────────────────────────────────────────────────

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
err()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || err "'$1' is required but not found"
}

# ── detect platform ────────────────────────────────────────────────────────────

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  os="linux"  ;;
    Darwin) os="macos"  ;;
    *)      err "Unsupported OS: $OS. Download manually from https://github.com/$REPO/releases" ;;
esac

case "$ARCH" in
    x86_64|amd64)   arch="x86_64" ;;
    arm64|aarch64)  arch="arm64"  ;;
    *)              err "Unsupported architecture: $ARCH. Download manually from https://github.com/$REPO/releases" ;;
esac

# ── homebrew path ──────────────────────────────────────────────────────────────

if command -v brew >/dev/null 2>&1; then
    say "Homebrew detected — installing via brew"
    brew tap immanuwell/droast https://github.com/immanuwell/homebrew-droast.git
    brew install immanuwell/droast/droast
    ok "droast installed via Homebrew"
    droast --version
    exit 0
fi

# ── binary download path ───────────────────────────────────────────────────────

need curl

say "Fetching latest release info..."
LATEST=$(curl -fsL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' \
    | sed 's/.*"tag_name" *: *"\([^"]*\)".*/\1/')

[ -n "$LATEST" ] || err "Could not determine latest release version"

ASSET="${BIN}-${os}-${arch}"
BASE_URL="https://github.com/$REPO/releases/download/$LATEST"

say "Installing $BIN $LATEST ($os/$arch)..."

TMP="$(mktemp)"
trap 'rm -f "$TMP" "$TMP.sums"' EXIT

curl -fsL "$BASE_URL/$ASSET"          -o "$TMP"
curl -fsL "$BASE_URL/sha256sums.txt"  -o "$TMP.sums"

# verify checksum
EXPECTED=$(grep "$ASSET\$" "$TMP.sums" | awk '{print $1}')
[ -n "$EXPECTED" ] || err "Could not find checksum for $ASSET in sha256sums.txt"

if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "$TMP" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "$TMP" | awk '{print $1}')
else
    err "Neither sha256sum nor shasum found — cannot verify download"
fi

[ "$ACTUAL" = "$EXPECTED" ] || err "Checksum mismatch (expected $EXPECTED, got $ACTUAL)"
ok "Checksum verified"

chmod +x "$TMP"

# ── install ────────────────────────────────────────────────────────────────────

# prefer /usr/local/bin if writable (e.g. already running as root / sudo sh)
# otherwise fall back to ~/.local/bin — avoids interactive sudo prompts that
# break when the script is piped from curl
if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP" "$INSTALL_DIR/$BIN"
    DEST="$INSTALL_DIR/$BIN"
else
    LOCAL_BIN="$HOME/.local/bin"
    mkdir -p "$LOCAL_BIN"
    mv "$TMP" "$LOCAL_BIN/$BIN"
    DEST="$LOCAL_BIN/$BIN"
    # warn if not in PATH
    case ":$PATH:" in
        *":$LOCAL_BIN:"*) ;;
        *) say "Note: add ~/.local/bin to your PATH:  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
    esac
fi

ok "$BIN $LATEST installed to $DEST"
"$DEST" --version
