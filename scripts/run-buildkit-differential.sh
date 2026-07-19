#!/usr/bin/env bash
set -euo pipefail

# Compare parser acceptance with BuildKit's `--call=check` without claiming that
# Dockerfile policy findings are byte-for-byte identical across tools.
repo_root="$(git rev-parse --show-toplevel)"
corpus="${1:-$repo_root/.droast-corpus}"
limit="${DROAST_DIFFERENTIAL_LIMIT:-0}"
buildkit_image="${DROAST_BUILDKIT_IMAGE:-moby/buildkit:v0.17.3}"
builder="droast-differential-$$"
droast_bin="$repo_root/target/release/droast"
results="$corpus/buildkit-differential.tsv"

command -v docker >/dev/null
docker buildx version >/dev/null
[[ -d "$corpus/files" ]] || { printf 'Corpus files are missing: %s\n' "$corpus/files" >&2; exit 1; }
if [[ ! -x "$droast_bin" ]]; then cargo build --release --locked --manifest-path "$repo_root/Cargo.toml"; fi

cleanup() { docker buildx rm --force "$builder" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker buildx create --name "$builder" --driver docker-container --driver-opt "image=$buildkit_image" --use >/dev/null
docker buildx inspect --bootstrap >/dev/null

printf 'path\tdroast_parser\tbuildkit_check\tclassification\n' > "$results"
mapfile -t files < <(find "$corpus/files" -type f -name '*.Dockerfile' -print | sort)
if (( limit > 0 && ${#files[@]} > limit )); then files=("${files[@]:0:limit}"); fi

for dockerfile in "${files[@]}"; do
  if "$droast_bin" --only DF071 --no-fail --no-roast --format json --check-dockerignore=false "$dockerfile" | jq -e '.findings | all(.rule != "DF071" or .severity != "ERROR")' >/dev/null; then
    droast_parser=accepted
  else
    droast_parser=rejected
  fi
  if docker buildx build --builder "$builder" --call=check --progress=quiet --file "$dockerfile" "$(dirname "$dockerfile")" >/dev/null 2>&1; then
    buildkit_check=accepted
  else
    buildkit_check=rejected
  fi
  if [[ "$droast_parser" == "$buildkit_check" ]]; then classification=match; else classification=delta; fi
  printf '%s\t%s\t%s\t%s\n' "$dockerfile" "$droast_parser" "$buildkit_check" "$classification" >> "$results"
done

matches="$(awk -F '\t' 'NR > 1 && $4 == "match" { count++ } END { print count+0 }' "$results")"
deltas="$(awk -F '\t' 'NR > 1 && $4 == "delta" { count++ } END { print count+0 }' "$results")"
printf 'BuildKit image: %s; files: %d; matches: %s; deltas: %s\n' "$buildkit_image" "${#files[@]}" "$matches" "$deltas"
printf 'Results: %s\n' "$results"
