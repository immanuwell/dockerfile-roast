#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
corpus="${1:-$repo_root/.droast-corpus}"
droast_bin="$repo_root/target/release/droast"
files_dir="$corpus/files"

[[ -f "$corpus/manifest.tsv" && -d "$files_dir" ]] || { printf 'Corpus is missing manifest.tsv or files/\n' >&2; exit 1; }
command -v sha256sum >/dev/null
cargo build --release --locked --manifest-path "$repo_root/Cargo.toml"

while IFS=$'\t' read -r id _ _ _ _ _ _ _ _ _ _ _ _ checksum local_path _; do
  [[ "$id" == id ]] && continue
  printf '%s  %s\n' "$checksum" "$corpus/$local_path"
done < "$corpus/manifest.tsv" | sha256sum --check --status

mapfile -t dockerfiles < <(find "$files_dir" -type f -name '*.Dockerfile' -print | sort)
(( ${#dockerfiles[@]} > 0 )) || { printf 'Corpus has no Dockerfiles\n' >&2; exit 1; }
"$droast_bin" --format sarif --no-roast --no-fail --check-dockerignore=false "${dockerfiles[@]}" > "$corpus/droast.sarif"
jq -e '.runs[0].results | type == "array"' "$corpus/droast.sarif" >/dev/null
"$droast_bin" fixes --format json "${dockerfiles[@]}" > "$corpus/fix-plans.json"
jq -n \
  --slurpfile sarif "$corpus/droast.sarif" \
  --slurpfile plans "$corpus/fix-plans.json" '
  def plan_list: if ($plans[0] | type) == "array" then $plans[0] else [$plans[0]] end;
  ($sarif[0].runs[0].results | length) as $total |
  ([plan_list[].fixes[]] // []) as $fixes |
  {
    schema_version: 1,
    total_findings: $total,
    fixable_findings: ($fixes | length),
    fixable_percent: (if $total == 0 then 0 else (($fixes | length) * 10000 / $total | round) / 100 end),
    edits: ([$fixes[].edits | length] | add // 0),
    rules: ($fixes | group_by(.rule) | map({key: .[0].rule, value: length}) | from_entries)
  }' > "$corpus/fixability.json"
jq -e '.schema_version == 1 and .fixable_findings >= 0' "$corpus/fixability.json" >/dev/null
printf 'Validated %d Dockerfiles; results: %s; fixability: %s\n' \
  "${#dockerfiles[@]}" "$corpus/droast.sarif" "$corpus/fixability.json"
