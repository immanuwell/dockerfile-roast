#!/usr/bin/env bash
# Build and validate the droast Wasmer package without publishing it.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$REPO_ROOT/wasmer.toml"
TARGET="wasm32-wasip1"
WASM="$REPO_ROOT/target/$TARGET/release/droast.wasm"
PACKAGE="$REPO_ROOT/target/wasmer/droast.webc"

for command in cargo jq wasmer; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required command not found: $command" >&2
        exit 1
    }
done

VERSION="$(cargo metadata --no-deps --format-version 1 --manifest-path "$REPO_ROOT/Cargo.toml" \
    | jq -r '.packages[] | select(.name == "dockerfile-roast") | .version')"
MANIFEST_VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$MANIFEST")"

if [[ -n "${RELEASE_VERSION:-}" && "$RELEASE_VERSION" != "$VERSION" ]]; then
    echo "release version $RELEASE_VERSION does not match Cargo.toml version $VERSION" >&2
    exit 1
fi

if [[ "$MANIFEST_VERSION" != "$VERSION" ]]; then
    echo "wasmer.toml version $MANIFEST_VERSION does not match Cargo.toml version $VERSION" >&2
    exit 1
fi

rustup target add "$TARGET" >/dev/null
DROAST_VERSION="$VERSION" cargo build \
    --locked \
    --release \
    --target "$TARGET" \
    --bin droast \
    --manifest-path "$REPO_ROOT/Cargo.toml"

if command -v wasm-tools >/dev/null 2>&1; then
    wasm-tools validate "$WASM"
fi

mkdir -p "$(dirname "$PACKAGE")"
PACKAGE_TMP_DIR="$(mktemp -d "$(dirname "$PACKAGE")/.droast.XXXXXX")"
PACKAGE_TMP="$PACKAGE_TMP_DIR/droast.webc"
trap 'rm -f "$PACKAGE_TMP"; rmdir "$PACKAGE_TMP_DIR" 2>/dev/null || true' EXIT
wasmer package build --out "$PACKAGE_TMP" "$REPO_ROOT"
mv "$PACKAGE_TMP" "$PACKAGE"
rmdir "$PACKAGE_TMP_DIR"
trap - EXIT

ACTUAL_VERSION="$(wasmer run "$REPO_ROOT" -- --version)"
if [[ "$ACTUAL_VERSION" != "droast $VERSION" ]]; then
    echo "unexpected Wasmer package version: $ACTUAL_VERSION" >&2
    exit 1
fi

echo "Built and validated $PACKAGE (droast $VERSION)."
