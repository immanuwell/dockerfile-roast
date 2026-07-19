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

install_data="$(mktemp -d)"
DROAST_NEOVIM_REPOSITORY="$repo_root" XDG_DATA_HOME="$install_data" \
  "$repo_root/scripts/install-neovim-extension.sh"
installed_plugin="$install_data/nvim/site/pack/droast/start/dockerfile-roast"
DROAST_REPO_ROOT="$repo_root" DROAST_INSTALLED_PLUGIN_ROOT="$installed_plugin" \
  "$nvim_bin" --headless -u NONE \
  -c "lua dofile('$repo_root/nvim/tests/install-e2e.lua')"
