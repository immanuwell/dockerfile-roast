#!/usr/bin/env bash
# Reproduce the published corpus statistics.
#
# Run corpus/rehydrate.sh first to reconstruct the Dockerfiles, then this
# script scans them with droast and prints the summary and the rule frequency
# table. Requires jq.
#
# Usage:
#   corpus/stats.sh                 use droast from PATH
#   DROAST=./target/release/droast corpus/stats.sh

set -euo pipefail

corpus_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
files_dir="$corpus_dir/files"
droast="${DROAST:-droast}"

if ! command -v "$droast" >/dev/null 2>&1 && [[ ! -x "$droast" ]]; then
  printf 'droast not found. Install it, or set DROAST=/path/to/droast.\n' >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required.\n' >&2
  exit 1
fi

if [[ ! -d "$files_dir" ]] || ! find "$files_dir" -name '*.Dockerfile' -print -quit | grep -q .; then
  printf 'No corpus files found. Run corpus/rehydrate.sh first.\n' >&2
  exit 1
fi

# --check-dockerignore=false matters: corpus samples are detached from their
# upstream build contexts, so DF033 would fire on every file for a missing
# .dockerignore that does exist in the real repository.
json="$("$droast" --no-fail --no-roast --check-dockerignore=false --format json "$files_dir")"

printf '\n== summary ==\n\n'
jq -r '
  (sort_by(.total) | map(.total)) as $t |
  "Files scanned          \(length)",
  "Total findings         \(map(.total) | add)",
  "  errors               \(map(.errors) | add)",
  "  warnings             \(map(.warnings) | add)",
  "  info                 \(map(.infos) | add)",
  "",
  "Median findings/file   \($t[(length / 2 | floor)])",
  "p90                    \($t[(length * 0.9 | floor)])",
  "Worst single file      \($t[-1])",
  "",
  "Files with >=1 warning or error   \([.[] | select(.errors + .warnings > 0)] | length)",
  "Files with zero errors            \([.[] | select(.errors == 0)] | length)",
  "Files with zero findings          \([.[] | select(.total == 0)] | length)"
' <<< "$json"

printf '\n== rules by share of files affected ==\n\n'
jq -r --argjson n "$(jq 'length' <<< "$json")" '
  [.[] | [.findings[].rule] | unique] | flatten | group_by(.)
  | map({rule: .[0], files: length}) | sort_by(-.files) | .[:15][]
  | "\(.rule)  \(.files)  \((.files / $n * 1000 | round / 10))%"
' <<< "$json"

printf '\n'
