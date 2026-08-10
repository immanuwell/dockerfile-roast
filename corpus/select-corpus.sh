#!/usr/bin/env bash
set -euo pipefail

corpus_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
files_dir="$corpus_dir/files"
work_dir="$(mktemp -d)"
target_count=150
retrieved_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT

if [[ -d "$files_dir" ]] && find "$files_dir" -type f -print -quit | grep -q .; then
  printf 'Corpus already exists at %s; remove its files explicitly before refreshing.\n' "$files_dir" >&2
  exit 1
fi

mkdir -p "$files_dir"

repos=(
  "moby/buildkit|12"
  "docker/buildx|8"
  "docker/compose|10"
  "moby/moby|10"
  "kubernetes/kubernetes|10"
  "grafana/grafana|10"
  "prometheus/prometheus|2"
  "argoproj/argo-cd|6"
  "aquasecurity/trivy|10"
  "go-gitea/gitea|2"
  "gitlabhq/gitlabhq|6"
  "nextcloud/docker|10"
  "supabase/supabase|3"
  "airbytehq/airbyte|10"
  "mattermost/mattermost|8"
  "apache/airflow|10"
  "apache/superset|6"
  "apache/kafka|3"
  "apache/pulsar|3"
  "envoyproxy/envoy|4"
  "istio/istio|10"
  "cilium/cilium|10"
  "goharbor/harbor|10"
  "traefik/traefik|1"
  "hashicorp/terraform|1"
  "linuxserver/docker-baseimage-alpine|2"
  "bitnami/containers|10"
)

printf 'id\trepository\tcommit\tbranch\tupstream_path\tsource_url\tlicense\tbytes\tlines\tstages\tmultistage\thas_heredoc\thas_run_mount\tsha256\tlocal_path\tretrieved_at\n' > "$corpus_dir/manifest.tsv"
printf 'repository\tcommit\tbranch\tlicense\tselected\n' > "$corpus_dir/repositories.tsv"

sample_number=0

for entry in "${repos[@]}"; do
  if (( sample_number >= target_count )); then
    break
  fi

  repo="${entry%%|*}"
  cap="${entry##*|}"
  repo_meta="$work_dir/repo-meta.json"
  tree_json="$work_dir/tree.json"
  candidates="$work_dir/candidates.tsv"
  qualified="$work_dir/qualified.tsv"
  repo_files="$work_dir/repo-files"

  rm -rf "$repo_files"
  mkdir -p "$repo_files"
  : > "$qualified"

  if ! gh api "repos/$repo" > "$repo_meta" 2>/dev/null; then
    printf 'Skipping unavailable repository %s\n' "$repo" >&2
    continue
  fi

  branch="$(jq -r '.default_branch' "$repo_meta")"
  license="$(jq -r '.license.spdx_id // "NOASSERTION"' "$repo_meta")"
  commit="$(gh api "repos/$repo/commits/$branch" --jq .sha)"

  if ! gh api "repos/$repo/git/trees/$commit?recursive=1" > "$tree_json" 2>/dev/null; then
    printf 'Skipping repository with unavailable tree %s\n' "$repo" >&2
    continue
  fi

  jq -r '
    .tree[]
    | select(.type == "blob")
    | select(.size >= 500 and .size <= 200000)
    | select(.path | test("(^|/)(Dockerfile|Containerfile)([._-][A-Za-z0-9_-]+)?$"; "i"))
    | select(.path | test("(^|/)(test|tests|testdata|fixtures|examples?|docs?|hack|vendor|integration|e2e)(/|$)"; "i") | not)
    | [.path, .size, .sha]
    | @tsv
  ' "$tree_json" | sort -t $'\t' -k2,2nr > "$candidates"

  candidate_number=0
  while IFS=$'\t' read -r upstream_path tree_size blob_sha; do
    [[ -n "$upstream_path" ]] || continue
    candidate_number=$((candidate_number + 1))
    downloaded="$repo_files/$candidate_number"
    source_url="https://raw.githubusercontent.com/$repo/$commit/$upstream_path"

    if ! curl --globoff -fsSL --retry 2 "$source_url" -o "$downloaded"; then
      rm -f "$downloaded"
      continue
    fi

    if file --brief --mime-type "$downloaded" | grep -qvE '^(text/|application/(json|xml|x-empty))'; then
      rm -f "$downloaded"
      continue
    fi

    # Keep the primary corpus limited to raw Dockerfile syntax. Files such as
    # dockerfile_*_test.go and Jinja/Mustache/Groovy templates can contain many
    # embedded FROM lines but are not Dockerfiles until another tool renders or
    # extracts them.
    if ! awk '/^[[:space:]]*FROM[[:space:]]+/{found=1} END {exit !found}' "$downloaded"; then
      rm -f "$downloaded"
      continue
    fi
    if awk '
      /^[[:space:]]*#/ { next }
      /<%|%>|\{\{|\{%|%%[A-Z][A-Z0-9_]*%%/ { found=1 }
      /@[A-Z][A-Z0-9_]*@/ { found=1 }
      END { exit !found }
    ' "$downloaded"; then
      rm -f "$downloaded"
      continue
    fi

    lines="$(awk 'END {print NR}' "$downloaded")"
    stages="$(awk 'toupper($1) == "FROM" {count++} END {print count+0}' "$downloaded")"
    if (( lines < 25 || stages < 1 )); then
      rm -f "$downloaded"
      continue
    fi

    bytes="$(stat -c %s "$downloaded")"
    if (( stages > 1 )); then multistage=1; else multistage=0; fi
    if rg -q '<<-?[A-Za-z_"'"'"'\\]' "$downloaded"; then has_heredoc=1; else has_heredoc=0; fi
    if rg -qi '^\s*RUN\s+--mount=' "$downloaded"; then has_run_mount=1; else has_run_mount=0; fi
    sha256="$(sha256sum "$downloaded" | cut -d' ' -f1)"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$multistage" "$lines" "$candidate_number" "$upstream_path" "$source_url" "$bytes" \
      "$stages" "$has_heredoc" "$has_run_mount" "$sha256" "$tree_size" "$blob_sha" >> "$qualified"
  done < "$candidates"

  selected_for_repo=0
  while IFS=$'\t' read -r multistage lines candidate_number upstream_path source_url bytes stages has_heredoc has_run_mount sha256 tree_size blob_sha; do
    if (( selected_for_repo >= cap || sample_number >= target_count )); then
      break
    fi

    sample_number=$((sample_number + 1))
    selected_for_repo=$((selected_for_repo + 1))
    sample_id="$(printf 'sample-%03d' "$sample_number")"
    local_path="files/$sample_id.Dockerfile"
    mv "$repo_files/$candidate_number" "$corpus_dir/$local_path"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$sample_id" "$repo" "$commit" "$branch" "$upstream_path" "$source_url" "$license" \
      "$bytes" "$lines" "$stages" "$multistage" "$has_heredoc" "$has_run_mount" "$sha256" \
      "$local_path" "$retrieved_at" >> "$corpus_dir/manifest.tsv"
  done < <(sort -t $'\t' -k1,1nr -k2,2nr "$qualified")

  printf '%s\t%s\t%s\t%s\t%s\n' "$repo" "$commit" "$branch" "$license" "$selected_for_repo" >> "$corpus_dir/repositories.tsv"
  printf 'Selected %3d from %-40s (%3d total)\n' "$selected_for_repo" "$repo" "$sample_number"
done

if (( sample_number < 100 )); then
  printf 'Only %d qualifying files were collected; expected at least 100.\n' "$sample_number" >&2
  exit 1
fi

printf 'Collected %d Dockerfiles in %s\n' "$sample_number" "$corpus_dir"
