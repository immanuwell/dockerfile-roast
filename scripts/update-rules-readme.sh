#!/usr/bin/env bash
# update-rules-readme.sh — regenerate the "all rules" dropdown in README.md
#
# Usage:
#   ./scripts/update-rules-readme.sh
#
# Builds droast (if needed), runs --list-rules, and replaces the content
# between the BEGIN/END markers in README.md with the fresh output.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
README="$REPO_ROOT/README.md"

log() { printf '\033[1;34m=>\033[0m %s\n' "$*"; }
ok()  { printf '\033[1;32m✓\033[0m  %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ── build ─────────────────────────────────────────────────────────────────────

log "Building droast..."
cargo build -q --manifest-path "$REPO_ROOT/Cargo.toml" 2>&1 \
    || die "cargo build failed"

DROAST="$REPO_ROOT/target/debug/droast"
[[ -x "$DROAST" ]] || die "binary not found at $DROAST"

# ── generate rule list ────────────────────────────────────────────────────────

log "Generating rule list..."

# strip ANSI escape codes and trim leading/trailing blank lines
RULES="$("$DROAST" --list-rules \
    | sed 's/\x1b\[[0-9;]*m//g' \
    | sed 's/[[:space:]]*$//' \
    | sed '/./,$!d' \
    | sed -e :a -e '/^\n*$/{$d;N;ba}')"

# ── update README.md ──────────────────────────────────────────────────────────

MARKER_BEGIN="<!-- BEGIN RULES -->"
MARKER_END="<!-- END RULES -->"

grep -q "$MARKER_BEGIN" "$README" \
    || die "Marker '$MARKER_BEGIN' not found in README.md"

log "Updating README.md..."

# build the replacement block
BLOCK="$MARKER_BEGIN"$'\n'
BLOCK+="<details>"$'\n'
BLOCK+="<summary>all 63 rules</summary>"$'\n'
BLOCK+=''$'\n'
BLOCK+="\`\`\`"$'\n'
BLOCK+="$RULES"$'\n'
BLOCK+="\`\`\`"$'\n'
BLOCK+=''$'\n'
BLOCK+="</details>"$'\n'
BLOCK+="$MARKER_END"

# use awk to replace everything between the markers (inclusive)
awk -v block="$BLOCK" '
    /<!-- BEGIN RULES -->/ { print block; skip=1; next }
    /<!-- END RULES -->/   { skip=0; next }
    !skip                  { print }
' "$README" > "$README.tmp" && mv "$README.tmp" "$README"

ok "README.md updated"
