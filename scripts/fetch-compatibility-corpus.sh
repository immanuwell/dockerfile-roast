#!/usr/bin/env bash
set -euo pipefail

# Fetch a license-attributed, pinned corpus without committing third-party
# Dockerfiles. Requires gh, jq, curl, sha256sum, and rg.
repo_root="$(git rev-parse --show-toplevel)"
catalog="$repo_root/compatibility/corpus/repositories.tsv"
destination="${1:-$repo_root/.droast-corpus}"
target_count="${DROAST_CORPUS_TARGET:-2500}"
files_dir="$destination/files"
work_dir="$(mktemp -d)"
retrieved_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cleanup() { rm -rf "$work_dir"; }
trap cleanup EXIT

if [[ -e "$files_dir" ]] && find "$files_dir" -type f -print -quit | grep -q .; then
  printf 'Refusing to overwrite existing corpus files at %s\n' "$files_dir" >&2
  exit 1
fi
command -v gh >/dev/null
command -v jq >/dev/null
command -v curl >/dev/null
mkdir -p "$files_dir"

printf 'id\trepository\tcommit\tbranch\tupstream_path\tsource_url\tlicense\tbytes\tlines\tstages\tmultistage\thas_heredoc\thas_run_mount\tsha256\tlocal_path\tretrieved_at\n' > "$destination/manifest.tsv"
printf 'repository\tcommit\tbranch\tlicense\tselected\n' > "$destination/repositories.tsv"
selected=0

while IFS=$'\t' read -r repository cap; do
  [[ -n "$repository" && "$repository" != \#* ]] || continue
  (( selected < target_count )) || break
  metadata="$work_dir/metadata.json"
  tree="$work_dir/tree.json"
  candidates="$work_dir/candidates.tsv"
  gh api "repos/$repository" > "$metadata"
  branch="$(jq -r .default_branch "$metadata")"
  license="$(jq -r '.license.spdx_id // "NOASSERTION"' "$metadata")"
  commit="$(gh api "repos/$repository/commits/$branch" --jq .sha)"
  gh api "repos/$repository/git/trees/$commit?recursive=1" > "$tree"
  jq -r '.tree[] | select(.type == "blob") | select(.size >= 500 and .size <= 200000) | select(.path | test("(^|/)(Dockerfile|Containerfile)([._-].*)?$"; "i")) | select(.path | test("(^|/)(test|tests|testdata|fixture|fixtures|example|examples|doc|docs|vendor|integration|e2e)(/|$)"; "i") | not) | [.path, .size] | @tsv' "$tree" | sort -t $'\t' -k2,2nr > "$candidates"
  repository_selected=0
  while IFS=$'\t' read -r upstream_path _; do
    (( repository_selected < cap && selected < target_count )) || break
    local_path="files/$(printf 'sample-%05d.Dockerfile' "$((selected + 1))")"
    temporary="$work_dir/sample"
    source_url="https://raw.githubusercontent.com/$repository/$commit/$upstream_path"
    curl --globoff -fsSL --retry 2 "$source_url" -o "$temporary" || continue
    file --brief --mime-type "$temporary" | grep -qE '^(text/|application/(json|xml|x-empty))' || continue
    lines="$(awk 'END { print NR }' "$temporary")"
    stages="$(awk 'toupper($1) == "FROM" { count++ } END { print count+0 }' "$temporary")"
    (( lines >= 10 && stages >= 1 )) || continue
    bytes="$(stat -c %s "$temporary")"
    multistage=$(( stages > 1 ))
    rg -q '<<-?[A-Za-z_"'"'"'\\]' "$temporary" && heredoc=1 || heredoc=0
    rg -qi '^\s*RUN\s+--mount=' "$temporary" && mount=1 || mount=0
    sha256="$(sha256sum "$temporary" | cut -d' ' -f1)"
    mv "$temporary" "$destination/$local_path"
    selected=$((selected + 1)); repository_selected=$((repository_selected + 1))
    printf 'sample-%05d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$selected" "$repository" "$commit" "$branch" "$upstream_path" "$source_url" "$license" "$bytes" "$lines" "$stages" "$multistage" "$heredoc" "$mount" "$sha256" "$local_path" "$retrieved_at" >> "$destination/manifest.tsv"
  done < "$candidates"
  printf '%s\t%s\t%s\t%s\t%s\n' "$repository" "$commit" "$branch" "$license" "$repository_selected" >> "$destination/repositories.tsv"
  printf 'Selected %d samples from %s (%d total)\n' "$repository_selected" "$repository" "$selected"
done < "$catalog"

(( selected >= target_count )) || { printf 'Only collected %d of %d requested Dockerfiles\n' "$selected" "$target_count" >&2; exit 1; }
printf 'Collected %d pinned Dockerfiles in %s\n' "$selected" "$destination"
