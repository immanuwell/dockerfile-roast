#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
nvim_bin="${NVIM_BIN:-nvim}"
command -v "$nvim_bin" >/dev/null || {
  printf 'Neovim is required; install Neovim 0.9 or newer and rerun this test.\n' >&2
  exit 1
}
cargo build --release --locked --manifest-path "$repo_root/Cargo.toml"
DROAST_REPO_ROOT="$repo_root" "$nvim_bin" --headless -u NONE \
  -c "lua dofile('$repo_root/nvim/tests/e2e.lua')"
