#!/usr/bin/env bash
# build-release.sh — cross-compile droast for all platforms and upload to a GitHub release
#
# Usage:
#   ./scripts/build-release.sh 1.0.0
#
# Requirements:
#   - cargo-zigbuild  (cargo install cargo-zigbuild)
#   - zig             (in PATH)
#   - gh              (GitHub CLI, authenticated)
#   - rustup targets  (installed automatically if missing)

set -euo pipefail

RELEASE="${1:-}"
if [[ -z "$RELEASE" ]]; then
    echo "Usage: $0 <release-tag>  (e.g. $0 1.0.0)" >&2
    exit 1
fi

BINARY="droast"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/dist"

declare -A TARGETS=(
    ["x86_64-unknown-linux-gnu"]="droast-linux-x86_64"
    ["aarch64-unknown-linux-gnu"]="droast-linux-arm64"
    ["x86_64-apple-darwin"]="droast-macos-x86_64"
    ["aarch64-apple-darwin"]="droast-macos-arm64"
    ["x86_64-pc-windows-gnu"]="droast-windows-x86_64.exe"
)

# ── helpers ──────────────────────────────────────────────────────────────────

log()  { printf '\033[1;34m=>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✓\033[0m  %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

require() {
    command -v "$1" &>/dev/null || die "'$1' not found in PATH"
}

# ── preflight ────────────────────────────────────────────────────────────────

require cargo
require cargo-zigbuild
require zig
require gh

log "Verifying GitHub release '$RELEASE' exists..."
gh release view "$RELEASE" --repo "$(gh repo view --json nameWithOwner -q .nameWithOwner)" \
    &>/dev/null || die "Release '$RELEASE' not found. Create it first with: gh release create $RELEASE"

# ── build ────────────────────────────────────────────────────────────────────

mkdir -p "$OUT_DIR"

cd "$REPO_ROOT"

for TARGET in "${!TARGETS[@]}"; do
    ARTIFACT="${TARGETS[$TARGET]}"
    log "Building $TARGET → $ARTIFACT"

    # install target if missing
    if ! rustup target list --installed | grep -q "^$TARGET$"; then
        log "  Installing rustup target $TARGET..."
        rustup target add "$TARGET"
    fi

    cargo zigbuild --release --target "$TARGET" --bin "$BINARY" \
        2>&1 | grep -E '^(error|warning\[|Compiling|Finished)' || true

    # locate the compiled binary
    if [[ "$TARGET" == *windows* ]]; then
        SRC="$REPO_ROOT/target/$TARGET/release/${BINARY}.exe"
    else
        SRC="$REPO_ROOT/target/$TARGET/release/$BINARY"
    fi

    [[ -f "$SRC" ]] || die "Expected binary not found: $SRC"

    cp "$SRC" "$OUT_DIR/$ARTIFACT"
    ok "$ARTIFACT  ($(du -sh "$OUT_DIR/$ARTIFACT" | cut -f1))"
done

# ── checksums ────────────────────────────────────────────────────────────────

log "Generating checksums..."
cd "$OUT_DIR"
sha256sum droast-* > sha256sums.txt
ok "sha256sums.txt"

# ── upload ───────────────────────────────────────────────────────────────────

REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"

log "Uploading artifacts to release '$RELEASE' ($REPO)..."
gh release upload "$RELEASE" \
    droast-linux-x86_64 \
    droast-linux-arm64 \
    droast-macos-x86_64 \
    droast-macos-arm64 \
    droast-windows-x86_64.exe \
    sha256sums.txt \
    --repo "$REPO" \
    --clobber

echo ""
ok "All done. Artifacts uploaded to: https://github.com/$REPO/releases/tag/$RELEASE"

# ── cleanup ──────────────────────────────────────────────────────────────────

log "Cleaning up dist/..."
rm -rf "$OUT_DIR"
ok "dist/ removed"
