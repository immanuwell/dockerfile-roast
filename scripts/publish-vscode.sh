#!/usr/bin/env bash
# Manually build and publish platform-specific VS Code extension VSIXs.
#
# Usage:
#   ./scripts/publish-vscode.sh 1.3.0              # publish to Marketplace
#   ./scripts/publish-vscode.sh 1.3.0 --dry-run    # package only, no publish
#
# Requirements:
#   - gh    (GitHub CLI, authenticated)
#   - vsce  (npm install -g @vscode/vsce)
#   - node  (for npm pkg set)
#
# VSCE_PAT env var must be set (your VS Code Marketplace Personal Access Token).

set -euo pipefail

VERSION="${1:-}"
DRY_RUN=false
for arg in "$@"; do [[ "$arg" == "--dry-run" ]] && DRY_RUN=true; done

if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version> [--dry-run]  (e.g. $0 1.3.0)" >&2
    exit 1
fi

if ! $DRY_RUN && [[ -z "${VSCE_PAT:-}" ]]; then
    echo "ERROR: VSCE_PAT env var is not set. Export your Marketplace token:" >&2
    echo "  export VSCE_PAT=<your-token>" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXT_DIR="$REPO_ROOT/vscode-extension"
BIN_DIR="$EXT_DIR/bin"

log() { printf '\033[1;34m=>\033[0m %s\n' "$*"; }
ok()  { printf '\033[1;32m✓\033[0m  %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v gh   &>/dev/null || die "gh not found"
command -v vsce &>/dev/null || die "vsce not found — npm install -g @vscode/vsce"
command -v node &>/dev/null || die "node not found"

declare -A TARGETS=(
    ["linux-x64"]="droast-linux-x86_64"
    ["linux-arm64"]="droast-linux-arm64"
    ["darwin-x64"]="droast-macos-x86_64"
    ["darwin-arm64"]="droast-macos-arm64"
    ["win32-x64"]="droast-windows-x86_64.exe"
)

# ── set version ───────────────────────────────────────────────────────────────

log "Setting extension version to $VERSION..."
cd "$EXT_DIR"
npm pkg set version="$VERSION"
ok "package.json version = $VERSION"

# ── install deps ──────────────────────────────────────────────────────────────

log "Installing extension dependencies..."
npm install --silent
ok "dependencies installed"

# ── download binaries ─────────────────────────────────────────────────────────

log "Downloading binaries for release $VERSION..."
rm -f "$BIN_DIR"/droast-*   # clear any previous run

REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"

for VSCE_TARGET in "${!TARGETS[@]}"; do
    ASSET="${TARGETS[$VSCE_TARGET]}"
    log "  $ASSET"
    gh release download "$VERSION" \
        --pattern "$ASSET" \
        --dir "$BIN_DIR" \
        --repo "$REPO"
    [[ "$VSCE_TARGET" != "win32-x64" ]] && chmod +x "$BIN_DIR/$ASSET"
    ok "$ASSET"
done

# ── package + publish ─────────────────────────────────────────────────────────

cd "$EXT_DIR"

for VSCE_TARGET in "${!TARGETS[@]}"; do
    log "Packaging $VSCE_TARGET..."

    if $DRY_RUN; then
        vsce package --target "$VSCE_TARGET" -o "droast-${VERSION}-${VSCE_TARGET}.vsix"
        ok "droast-${VERSION}-${VSCE_TARGET}.vsix (dry run — not published)"
    else
        vsce publish --target "$VSCE_TARGET" -p "$VSCE_PAT"
        ok "published $VSCE_TARGET"
    fi
done

# ── cleanup ───────────────────────────────────────────────────────────────────

log "Cleaning up binaries..."
rm -f "$BIN_DIR"/droast-*
ok "done"

echo ""
if $DRY_RUN; then
    ok "VSIXs are in vscode-extension/. Inspect them, then run without --dry-run to publish."
else
    ok "All 5 platform VSIXs published to the Marketplace for version $VERSION."
fi
