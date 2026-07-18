#!/usr/bin/env bash
# Backward-compatible entry point; public metadata now shares one generator.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/update-public-metadata.sh" "$@"
