#!/usr/bin/env bash
set -euo pipefail

repository="${DROAST_NEOVIM_REPOSITORY:-https://github.com/immanuwell/dockerfile-roast.git}"
data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
destination="$data_home/nvim/site/pack/droast/start/dockerfile-roast"

command -v git >/dev/null || {
  printf 'git is required to install the Droast Neovim extension.\n' >&2
  exit 1
}
if [[ -e "$destination" ]]; then
  printf 'Droast Neovim extension is already installed at %s\n' "$destination" >&2
  printf 'Remove that exact directory before reinstalling.\n' >&2
  exit 1
fi

mkdir -p "$(dirname "$destination")"
git clone --depth=1 "$repository" "$destination"
ln -s nvim/plugin "$destination/plugin"
ln -s nvim/lua "$destination/lua"
printf 'Installed the Droast Neovim extension. Restart Neovim to enable it.\n'
