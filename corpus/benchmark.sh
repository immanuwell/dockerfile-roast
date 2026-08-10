#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
benchmark_dir="$repo_root/.droast-benchmark"
corpus_dir="$repo_root/.droast-corpus/files"
droast_bin="$repo_root/target/release/droast"
hadolint_bin="$(command -v hadolint)"
iterations="${1:-30}"

if [[ ! -x "$droast_bin" ]]; then
  cargo build --release --manifest-path "$repo_root/Cargo.toml"
fi

mapfile -t corpus_files < <(find "$corpus_dir" -type f -name '*.Dockerfile' -print | sort)
if (( ${#corpus_files[@]} == 0 )); then
  printf 'No Dockerfiles found under %s\n' "$corpus_dir" >&2
  exit 1
fi

droast_cmd=(
  "$droast_bin"
  --config /dev/null
  --format sarif
  --no-roast
  --no-fail
  --check-dockerignore=false
  "${corpus_files[@]}"
)
hadolint_cmd=(
  "$hadolint_bin"
  --config "$benchmark_dir/hadolint-empty.yaml"
  --no-fail
  --format sarif
  "${corpus_files[@]}"
)

for _ in 1 2 3; do
  "${droast_cmd[@]}" > /dev/null
  "${hadolint_cmd[@]}" > /dev/null
done

printf 'tool\titeration\telapsed_ms\n' > "$benchmark_dir/timings.tsv"

measure() {
  local tool="$1"
  local iteration="$2"
  shift 2
  local start_ns end_ns elapsed_ms
  start_ns="$(date +%s%N)"
  "$@" > /dev/null
  end_ns="$(date +%s%N)"
  elapsed_ms="$(awk -v start="$start_ns" -v end="$end_ns" 'BEGIN {printf "%.3f", (end-start)/1000000}')"
  printf '%s\t%s\t%s\n' "$tool" "$iteration" "$elapsed_ms" >> "$benchmark_dir/timings.tsv"
}

for ((iteration=1; iteration<=iterations; iteration++)); do
  if (( iteration % 2 == 1 )); then
    measure droast "$iteration" "${droast_cmd[@]}"
    measure hadolint "$iteration" "${hadolint_cmd[@]}"
  else
    measure hadolint "$iteration" "${hadolint_cmd[@]}"
    measure droast "$iteration" "${droast_cmd[@]}"
  fi
done

"${droast_cmd[@]}" > "$benchmark_dir/droast-results.sarif"
"${hadolint_cmd[@]}" > "$benchmark_dir/hadolint-results.sarif"

summarize_timings() {
  local tool="$1"
  local values="$benchmark_dir/$tool-timings.sorted"
  awk -F'\t' -v tool="$tool" 'NR>1 && $1==tool {print $3}' "$benchmark_dir/timings.tsv" | sort -n > "$values"
  awk '
    {value[NR]=$1; sum+=$1}
    END {
      if (NR % 2 == 0) median=(value[NR/2]+value[NR/2+1])/2; else median=value[(NR+1)/2];
      p95_index=int((NR*95+99)/100);
      printf "%.3f\t%.3f\t%.3f\t%.3f\t%.3f\n", value[1], median, value[p95_index], sum/NR, value[NR];
    }
  ' "$values"
}

droast_timing="$(summarize_timings droast)"
hadolint_timing="$(summarize_timings hadolint)"

total_lines="$(find "$corpus_dir" -type f -name '*.Dockerfile' -print0 | xargs -0 wc -l | awk 'END {print $1}')"
droast_findings="$(jq '.runs[0].results | length' "$benchmark_dir/droast-results.sarif")"
hadolint_findings="$(jq '.runs[0].results | length' "$benchmark_dir/hadolint-results.sarif")"

count_level() {
  local sarif="$1"
  local level="$2"
  jq --arg level "$level" '[.runs[0].results[] | select(.level == $level)] | length' "$sarif"
}

IFS=$'\t' read -r droast_min droast_median droast_p95 droast_mean droast_max <<< "$droast_timing"
IFS=$'\t' read -r hadolint_min hadolint_median hadolint_p95 hadolint_mean hadolint_max <<< "$hadolint_timing"

droast_size="$(stat -c %s "$droast_bin")"
hadolint_size="$(stat -c %s "$hadolint_bin")"
speedup="$(awk -v slow="$hadolint_median" -v fast="$droast_median" 'BEGIN {printf "%.2f", slow/fast}')"
size_ratio="$(awk -v large="$hadolint_size" -v small="$droast_size" 'BEGIN {printf "%.2f", large/small}')"
droast_files_per_second="$(awk -v files="${#corpus_files[@]}" -v ms="$droast_median" 'BEGIN {printf "%.1f", files*1000/ms}')"
hadolint_files_per_second="$(awk -v files="${#corpus_files[@]}" -v ms="$hadolint_median" 'BEGIN {printf "%.1f", files*1000/ms}')"
droast_lines_per_second="$(awk -v lines="$total_lines" -v ms="$droast_median" 'BEGIN {printf "%.0f", lines*1000/ms}')"
hadolint_lines_per_second="$(awk -v lines="$total_lines" -v ms="$hadolint_median" 'BEGIN {printf "%.0f", lines*1000/ms}')"

printf 'metric\tdroast\thadolint\n' > "$benchmark_dir/metrics.tsv"
printf 'version\t%s\t%s\n' "$($droast_bin --version)" "$($hadolint_bin --version)" >> "$benchmark_dir/metrics.tsv"
printf 'binary_bytes\t%s\t%s\n' "$droast_size" "$hadolint_size" >> "$benchmark_dir/metrics.tsv"
printf 'files\t%s\t%s\n' "${#corpus_files[@]}" "${#corpus_files[@]}" >> "$benchmark_dir/metrics.tsv"
printf 'lines\t%s\t%s\n' "$total_lines" "$total_lines" >> "$benchmark_dir/metrics.tsv"
printf 'findings\t%s\t%s\n' "$droast_findings" "$hadolint_findings" >> "$benchmark_dir/metrics.tsv"
printf 'errors\t%s\t%s\n' "$(count_level "$benchmark_dir/droast-results.sarif" error)" "$(count_level "$benchmark_dir/hadolint-results.sarif" error)" >> "$benchmark_dir/metrics.tsv"
printf 'warnings\t%s\t%s\n' "$(count_level "$benchmark_dir/droast-results.sarif" warning)" "$(count_level "$benchmark_dir/hadolint-results.sarif" warning)" >> "$benchmark_dir/metrics.tsv"
printf 'notes\t%s\t%s\n' "$(count_level "$benchmark_dir/droast-results.sarif" note)" "$(count_level "$benchmark_dir/hadolint-results.sarif" note)" >> "$benchmark_dir/metrics.tsv"
printf 'min_ms\t%s\t%s\n' "$droast_min" "$hadolint_min" >> "$benchmark_dir/metrics.tsv"
printf 'median_ms\t%s\t%s\n' "$droast_median" "$hadolint_median" >> "$benchmark_dir/metrics.tsv"
printf 'p95_ms\t%s\t%s\n' "$droast_p95" "$hadolint_p95" >> "$benchmark_dir/metrics.tsv"
printf 'mean_ms\t%s\t%s\n' "$droast_mean" "$hadolint_mean" >> "$benchmark_dir/metrics.tsv"
printf 'max_ms\t%s\t%s\n' "$droast_max" "$hadolint_max" >> "$benchmark_dir/metrics.tsv"
printf 'files_per_second\t%s\t%s\n' "$droast_files_per_second" "$hadolint_files_per_second" >> "$benchmark_dir/metrics.tsv"
printf 'lines_per_second\t%s\t%s\n' "$droast_lines_per_second" "$hadolint_lines_per_second" >> "$benchmark_dir/metrics.tsv"
printf 'speedup\t%s\t1.00\n' "$speedup" >> "$benchmark_dir/metrics.tsv"
printf 'size_advantage\t%s\t1.00\n' "$size_ratio" >> "$benchmark_dir/metrics.tsv"

printf 'Completed %d interleaved runs per tool across %d files and %s lines.\n' "$iterations" "${#corpus_files[@]}" "$total_lines"
printf 'Median: droast %s ms, Hadolint %s ms (%sx faster).\n' "$droast_median" "$hadolint_median" "$speedup"
