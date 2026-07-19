#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
corpus="${1:-$repo_root/.droast-corpus}"
droast_bin="$repo_root/target/release/droast"
files_dir="$corpus/files"

[[ -f "$corpus/manifest.tsv" && -d "$files_dir" ]] || { printf 'Corpus is missing manifest.tsv or files/\n' >&2; exit 1; }
command -v sha256sum >/dev/null
if [[ ! -x "$droast_bin" ]]; then cargo build --release --locked --manifest-path "$repo_root/Cargo.toml"; fi

while IFS=$'\t' read -r id _ _ _ _ _ _ _ _ _ _ _ _ checksum local_path _; do
  [[ "$id" == id ]] && continue
  printf '%s  %s\n' "$checksum" "$corpus/$local_path"
done < "$corpus/manifest.tsv" | sha256sum --check --status

mapfile -t dockerfiles < <(find "$files_dir" -type f -name '*.Dockerfile' -print | sort)
(( ${#dockerfiles[@]} > 0 )) || { printf 'Corpus has no Dockerfiles\n' >&2; exit 1; }
"$droast_bin" --format sarif --no-roast --no-fail --check-dockerignore=false "${dockerfiles[@]}" > "$corpus/droast.sarif"
jq -e '.runs[0].results | type == "array"' "$corpus/droast.sarif" >/dev/null
printf 'Validated %d Dockerfiles; results: %s\n' "${#dockerfiles[@]}" "$corpus/droast.sarif"
