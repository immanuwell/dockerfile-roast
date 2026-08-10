#!/usr/bin/env bash
# Rebuild the exact validation corpus from manifest.tsv.
#
# Every row in the manifest pins a source URL to an immutable commit SHA and
# records the SHA-256 of the file at that commit, so this reconstructs the
# same 649 Dockerfiles the published measurements were taken on. Files whose
# checksum does not match are rejected rather than silently accepted.
#
# The Dockerfiles themselves are not redistributed in this repository; they
# remain under their own upstream licenses. This script fetches them from
# their origin on your machine.
#
# Usage:
#   corpus/rehydrate.sh                 fetch into corpus/files/
#   corpus/rehydrate.sh --verify-only   check existing files, download nothing
#   corpus/rehydrate.sh --jobs 8        parallel downloads (default 6)

set -euo pipefail

corpus_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest="$corpus_dir/manifest.tsv"
files_dir="$corpus_dir/files"
jobs=6
verify_only=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify-only) verify_only=1; shift ;;
    --jobs) jobs="${2:?--jobs needs a number}"; shift 2 ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

if [[ ! -f "$manifest" ]]; then
  printf 'manifest not found: %s\n' "$manifest" >&2
  exit 1
fi

mkdir -p "$files_dir"

fetch_one() {
  local id="$1" url="$2" want="$3" dest="$4" verify_only="$5"

  if [[ -f "$dest" ]]; then
    local have
    have="$(sha256sum "$dest" | cut -d' ' -f1)"
    if [[ "$have" == "$want" ]]; then
      printf 'ok       %s\n' "$id"
      return 0
    fi
    printf 'stale    %s (checksum differs, refetching)\n' "$id"
    rm -f "$dest"
  fi

  if [[ "$verify_only" == "1" ]]; then
    printf 'MISSING  %s\n' "$id"
    return 1
  fi

  local tmp
  tmp="$(mktemp)"
  if ! curl --globoff -fsSL --retry 3 --max-time 60 "$url" -o "$tmp"; then
    rm -f "$tmp"
    printf 'FETCH    %s (%s)\n' "$id" "$url"
    return 1
  fi

  local have
  have="$(sha256sum "$tmp" | cut -d' ' -f1)"
  if [[ "$have" != "$want" ]]; then
    rm -f "$tmp"
    printf 'CHECKSUM %s (expected %s, got %s)\n' "$id" "$want" "$have"
    return 1
  fi

  mv "$tmp" "$dest"
  printf 'fetched  %s\n' "$id"
}
export -f fetch_one

status_file="$(mktemp)"
trap 'rm -f "$status_file"' EXIT

tail -n +2 "$manifest" \
  | awk -F'\t' -v dir="$files_dir" -v vo="$verify_only" \
      '{ n = split($15, p, "/"); print $1 "\t" $6 "\t" $14 "\t" dir "/" p[n] "\t" vo }' \
  | xargs -P "$jobs" -I{} bash -c '
      IFS=$'"'"'\t'"'"' read -r id url want dest vo <<< "{}"
      fetch_one "$id" "$url" "$want" "$dest" "$vo"
    ' \
  | tee "$status_file"

total=$(( $(wc -l < "$manifest") - 1 ))
good=$(grep -cE '^(ok|fetched) ' "$status_file" || true)
bad=$(( total - good ))

printf '\n'
printf 'manifest entries : %s\n' "$total"
printf 'verified         : %s\n' "$good"
printf 'failed           : %s\n' "$bad"

if [[ "$bad" -ne 0 ]]; then
  printf '\nSome entries could not be verified. Upstream repositories occasionally\n'
  printf 'rewrite history or go private, which makes a pinned commit unreachable.\n'
  exit 1
fi

printf '\nCorpus reconstructed at %s\n' "$files_dir"
printf 'Reproduce the published numbers with: corpus/stats.sh\n'
